# MLPS "FFaust"

(Multiple Launch Packet System)

```
   ____       ________   ____                 __ 
  / __ \_  __/ __/ __/  / __/___ ___  _______/ /_
 / / / / |/_/ /_/ /_   / /_/ __ `/ / / / ___/ __/
/ /_/ />  </ __/ __/  / __/ /_/ / /_/ (__  ) /_  
\____/_/|_/_/ /_/    /_/  \__,_/\__,_/____/\__/  
```

High-performance TCP SYN flooding tool. `ffaust` manipulates packets directly on Ethernet layer and achieves up to 2.5M pps (packets per second) on a single machine.

## Disclaimer

MLPS "FFaust" is a stress testing tool and it is not to be used on targets that you do not have explicit consent to attack.

## Attack vector

A SYN flood attack is a common form of a denial of service attack in which an attacker sends a sequence of SYN requests to the target system (can be a router, firewall, Intrusion Prevention Systems (IPS), etc.) in order to consume its resources, preventing legitimate clients from establishing a regular connection. This DOS attack exhausts a server's memory & CPU and not necessarily bandwidth (which other attacks like ICMP/Ping Flooding do).

At a high level, how this works is that we craft our own TCP SYN packets and then completely flood a server with them. When we send a SYN packet, the server will respond with a SYN-ACK and allocate some memory in the kernel buffer in an attempt to set up a new connection with us (at this point the connection is "half open" which is why the SYN Flooding Attack is also known as the "Half Open Attack"). The half open connections can be seen on the server side with netstat -nt4 | grep "SYN_RECV". By sending multiple SYNs per second, we cantry to get the server to exhaust it's memory and thus make it to be unable to serve legitimate clients.

## Install

To compile from source:

```shell
git clone https://github.com/0xffiber/ffaust.git
cd ffaust
cargo build --release
```

## Usage

Run the tool:

```shell
$ target/release/ffaust 169.172.1.1:80 10.0.1.5:443
   ____       ________   ____                 __
  / __ \_  __/ __/ __/  / __/___ ___  _______/ /_
 / / / / |/_/ /_/ /_   / /_/ __ `/ / / / ___/ __/
/ /_/ />  </ __/ __/  / __/ /_/ / /_/ (__  ) /_
\____/_/|_/_/ /_/    /_/  \__,_/\__,_/____/\__/

Preparing config... DONE
Source:
  iface eth0
  inet 10.0.0.6
  gw 10.0.0.1
  ether 00:00:00:9a:5f:55
  dest 12:34:56:00:00:00

==> 1s sent: 1,636,753 (1,636,753 pps) traffic: 103.02 MiB (103.02 MiB/s)
==> 2s sent: 3,333,556 (1,666,778 pps) traffic: 209.82 MiB (104.91 MiB/s)
==> 3s sent: 5,012,894 (1,670,964 pps) traffic: 315.52 MiB (105.17 MiB/s)
==> 4s sent: 6,672,925 (1,668,231 pps) traffic: 420.01 MiB (105.00 MiB/s)
==> 5s sent: 8,397,134 (1,679,426 pps) traffic: 528.54 MiB (105.71 MiB/s)
```

To get max performance make sure to properly set number of sender threads (typically number of cores - 2).

Full list of options:

```shell
ffaust 0.1.0

USAGE:
    ffaust [OPTIONS] [TARGET]...

ARGS:
    <TARGET>...    ip:port pair to stress out

OPTIONS:
    -g, --gateway-ip <GATEWAY_IP>            Specify gateway IP address
    -G, --gateway-mac <GATEWAY_MAC>          Specify gateway MAC address
    -h, --help                               Print help information
    -i, --interface <INTERFACE>              Specify network interface to use
    -s, --source-port <SOURCE_PORT>          Source port(s) for packets
    -S, --source-ip <SOURCE_IP>              Source address(es) for packets
    -T, --sender-threads <SENDER_THREADS>    Threads used to send packets  (default=`1')
    -V, --version                            Print version information
```

## Implementation Notes

The tool makes an attempt to identify default interface to run the attack. If the default one could not be detected, please make sure to pass interface name with arguments.

In you have multiple interfaces with external connectivity, you can specify all of them (comma-separated).

Destination MAC is resolved once before launching the attack (using ARP protocol).

Full ethernet packet for each (source -> destination) pair is generated only once. Each of the following packets is created by mutating only a few bytes in the payload (and recomputing TCP header checksum).

## TODO

The tool is under active development:

- [ ] Support IP ranges for source IP
- [ ] Support source IP spoofing (with flag)
- [ ] Option to read config from stdin, resolve for hostnames
