```
    ________                 __ 
   / __/ __/___ ___  _______/ /_
  / /_/ /_/ __ `/ / / / ___/ __/
 / __/ __/ /_/ / /_/ (__  ) /_  
/_/ /_/  \__,_/\__,_/____/\__/  
```

A high performance TCP SYN flooding tool. By operating directly with ethernet packets to bypass kernel TCP stack, `ffaust` achieves up to 2.5M pps (packets per second) on a single machine.

## Disclaimer

"ffaust' is a stress testing tool and it is not to be used on targets that you do not have explicit consent to attack.

## Attack vector

A SYN flood attack is a common form of a denial of service attack in which an attacker sends a sequence of SYN requests to the target system (can be a router, firewall, Intrusion Prevention Systems (IPS), etc.) in order to consume its resources, preventing legitimate clients from establishing a regular connection. This DOS attack exhausts a server's memory & CPU and not necessarily bandwidth (which other attacks like ICMP/Ping Flooding do).

At a high level, how this works is that we craft our own TCP SYN packets and then completely flood a server with them. When we send a SYN packet, the server will respond with a SYN-ACK and allocate some memory in the kernel buffer in an attempt to set up a new connection with us (at this point the connection is "half open" which is why the SYN Flooding Attack is also known as the "Half Open Attack"). The half open connections can be seen on the server side with netstat -nt4 | grep "SYN_RECV". By sending multiple SYNs per second, we cantry to get the server to exhaust it's memory and thus make it to be unable to serve legitimate clients.

## Install

To compile from source:

```shell
# git clone https://github.com/0xffiber/ffaust.git
# cd ffaust
# cargo build --release
```

## Usage

Run the tool:

```shell
# target/release/ffaust <IP> <PORT> [<IFACE>]
```

## TODO

The tool is under active development:

- [ ] Proper CLI args, advanced configuration for interface(s), IP ranges, etc
- [ ] Run multiple threads (test if this is going to be necessary againsts single IP address)
- [ ] Logger to print progress
- [ ] Support source IP spoofing (with flag)
- [ ] Multiple targets (ip/port pairs), option to read config from stdin, resolve for hostnames
- [ ] Settings for number of worker threads & total execution time
