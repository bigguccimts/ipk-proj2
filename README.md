# Documentation of IPK Project 2 - Zeta (Packet sniffer)

## Usage

```utf-8
./ipk-sniffer [-h | --help] [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```

```utf-8
-i | --interface interface - Specifies the interface where the sniffer will sniff packets. 
-t | --tcp                 - Only TCP segments will be displayed
-u | --udp                 - Only UDP datagrams will be displayed
-p port                    - If this parameter is not present, then no filtering by port number occurs. If yes, filtering by port will be applied to TCP and UDP
--icmp4                    - Only ICMPv4 packets will be displayed
--icmp6                    - Only ICMPv6 request/response packets will be displayed
--arp                      - Only ARP packets will be displayed
--ndp                      - Only NDP packets will be displayed
--igmp                     - Only IGMP packets will be displayed
--mld                      - Only MLD packets will be displayed
-n num                     - Specifies the number of packets to display, if not specified, application will display only 1 packet
-h | --help                - Prints help

If no protocols are specified, all packets will be outputted
If no arguments are specified or if only -i | --interface is specified without a value (and any other parameters are not specified), then a list of active interfaces will be printed
```

## Functionality

Application can be built using ```make```.

Based on specified command-line arguments, the application will create and apply a filter to intercepted packets and print their content to ```stdout```.

User can specify the duration of intercepting packets by specifying the ```-n``` command-line argument (ie. ```-n 10``` would intercept 10 packets).

User may terminate the sniffer using ```C-c``` at any given point of running the program.

Application utilizes ```libpcap``` library [1] to process packets.

Packet handling is done by ```pcap_loop``` function. It utilizes a handler function to process the packets:

```c++
void pcap_process_handler(u_char *foo, const struct pcap_pkthdr *pckt_header, const u_char *packet)
{

    (void)foo;
    struct ether_header *ethernet_frame_h = (struct ether_header *)packet;
    struct ether_arp *arp_frame_h;
    processed_data_t data;

    data.src_port_num = -1;
    data.dst_port_num = -1;

    data.frame_length = (int)pckt_header->len;
    data.src_mac = parse_mac_addr(ethernet_frame_h->ether_shost);
    data.dst_mac = parse_mac_addr(ethernet_frame_h->ether_dhost);
    struct tcphdr *tcp_segment;
    struct udphdr *udp_datagram;
    switch (ntohs(ethernet_frame_h->ether_type))
    {
    case ETHERTYPE_IP:
    {
        struct ip *ipv4_frame = (struct ip *)(packet + 14); // 14 bytes long ethernet headers
        // Storing port numbers
        switch (ipv4_frame->ip_p)
        {
        case IPPROTO_TCP:
            tcp_segment = (struct tcphdr *)(packet + 14 + ipv4_frame->ip_hl * 4); // IPv4 header needs to be multiplied by 4 to get bytes
            data.src_port_num = ntohs(tcp_segment->th_sport);
            data.dst_port_num = ntohs(tcp_segment->th_dport);
            break;
        case IPPROTO_UDP:
            udp_datagram = (struct udphdr *)(packet + 14 + ipv4_frame->ip_hl * 4);
            data.src_port_num = ntohs(udp_datagram->uh_sport);
            data.dst_port_num = ntohs(udp_datagram->uh_dport);
            break;
        }
        // ICMP and IGMP do not utilize ports so only src and dst IP addresses are being stored
        data.src_ip_addr = inet_ntoa(ipv4_frame->ip_src);
        data.dst_ip_addr = inet_ntoa(ipv4_frame->ip_dst);
        print_out(data, packet);
    }
    break;
    case ETHERTYPE_IPV6:
    {
        struct ip6_hdr *ipv6_frame = (struct ip6_hdr *)(packet + 14); // 14 bytes long ethernet headers

        switch (ipv6_frame->ip6_ctlun.ip6_un1.ip6_un1_nxt)
        {
        case IPPROTO_TCP:
            tcp_segment = (struct tcphdr *)(packet + 14 + 40); // IPv6 headers are always 40 bytes long
            data.src_port_num = ntohs(tcp_segment->th_sport);
            data.dst_port_num = ntohs(tcp_segment->th_dport);
            break;
        case IPPROTO_UDP:
            udp_datagram = (struct udphdr *)(packet + 14 + 40);
            data.src_port_num = ntohs(udp_datagram->uh_sport);
            data.dst_port_num = ntohs(udp_datagram->uh_dport);
            break;
        }
        // ICMPv6, MLD and NDP do not utilize ports so only src and dst IPv6 addresses are being stored
        data.src_ip_addr = parse_ipv6_addr(ipv6_frame->ip6_src);
        data.dst_ip_addr = parse_ipv6_addr(ipv6_frame->ip6_dst);
        print_out(data, packet);
    }
    break;
    case ETHERTYPE_ARP:
    {
        arp_frame_h = (struct ether_arp *)(packet + 14); // 14 bytes long ethernet headers
        data.src_ip_addr = parse_ip_addr(arp_frame_h->arp_spa);
        data.dst_ip_addr = parse_ip_addr(arp_frame_h->arp_tpa);
        data.src_mac = parse_mac_addr(arp_frame_h->arp_sha);
        data.dst_mac = parse_mac_addr(arp_frame_h->arp_tha);
        print_out(data, packet);
    }
    break;
    }
    return;
}
```

## Theory

### Ethernet frame

In computer networking, an Ethernet frame is a data link layer protocol data unit and uses the underlying Ethernet physical layer transport mechanisms. In other words, a data unit on an Ethernet link transports an Ethernet frame as its payload.

An Ethernet frame is preceded by a preamble and start frame delimiter (SFD), which are both part of the Ethernet packet at the physical layer. Each Ethernet frame starts with an Ethernet header, which contains destination and source MAC addresses as its first two fields. The middle section of the frame is payload data including any headers for other protocols (for example, Internet Protocol) carried in the frame. The frame ends with a frame check sequence (FCS), which is a 32-bit cyclic redundancy check used to detect any in-transit corruption of data. [2]

### IP Packets

#### IPv4 Packets

An IP packet consists of a header section and a data section. An IP packet has no data checksum or any other footer after the data section. Typically the link layer encapsulates IP packets in frames with a CRC footer that detects most errors, many transport-layer protocols carried by IP also have their own error checking.

The IPv4 packet header consists of 14 fields, of which 13 are required. The 14th field is optional and aptly named: options. The fields in the header are packed with the most significant byte first (network byte order), and for the diagram and discussion, the most significant bits are considered to come first (MSB 0 bit numbering). [3]

#### IPv6 Packets

An IPv6 packet is the smallest message entity exchanged using Internet Protocol version 6 (IPv6). Packets consist of control information for addressing and routing and a payload of user data. The control information in IPv6 packets is subdivided into a mandatory fixed header and optional extension headers. The payload of an IPv6 packet is typically a datagram or segment of the higher-level transport layer protocol, but may be data for an internet layer (e.g., ICMPv6) or link layer (e.g., OSPF) instead.

The fixed header starts an IPv6 packet and has a size of 40 octets (320 bits). [4]

### TCP

The Transmission Control Protocol (TCP) is one of the main protocols of the Internet protocol suite. It originated in the initial network implementation in which it complemented the Internet Protocol (IP).

TCP provides reliable, ordered, and error-checked delivery of a stream of octets (bytes) between applications running on hosts communicating via an IP network.

TCP is connection-oriented, and a connection between client and server is established before data can be sent. The server must be listening (passive open) for connection requests from clients before a connection is established. Three-way handshake (active open), retransmission, and error detection adds to reliability but lengthens latency. [5]

### UDP

In computer networking, the User Datagram Protocol (UDP) is one of the core communication protocols of the Internet protocol suite used to send messages (transported as datagrams in packets) to other hosts on an Internet Protocol (IP) network. Within an IP network, UDP does not require prior communication to set up communication channels or data paths.

UDP uses a simple connectionless communication model with a minimum of protocol mechanisms. UDP provides checksums for data integrity, and port numbers for addressing different functions at the source and destination of the datagram. It has no handshaking dialogues, and thus exposes the user's program to any unreliability of the underlying network; there is no guarantee of delivery, ordering, or duplicate protection.

UDP is suitable for purposes where error checking and correction are either not necessary or are performed in the application; UDP avoids the overhead of such processing in the protocol stack. Time-sensitive applications often use UDP because dropping packets is preferable to waiting for packets delayed due to retransmission, which may not be an option in a real-time system. [6]

### ICMPv4/ICMPv6

The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite. It is used by network devices, including routers, to send error messages and operational information indicating success or failure when communicating with another IP address, for example, an error is indicated when a requested service is not available or that a host or router could not be reached. ICMP differs from transport protocols such as TCP and UDP in that it is not typically used to exchange data between systems, nor is it regularly employed by end-user network applications (with the exception of some diagnostic tools like ping and traceroute).

The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite. It is used by network devices, including routers, to send error messages and operational information indicating success or failure when communicating with another IP address, for example, an error is indicated when a requested service is not available or that a host or router could not be reached. ICMP differs from transport protocols such as TCP and UDP in that it is not typically used to exchange data between systems, nor is it regularly employed by end-user network applications (with the exception of some diagnostic tools like ping and traceroute). [7]

Internet Control Message Protocol version 6 (ICMPv6) is the implementation of the Internet Control Message Protocol (ICMP) for Internet Protocol version 6 (IPv6). [8]

### ARP

The Address Resolution Protocol (ARP) is a communication protocol used for discovering the link layer address, such as a MAC address, associated with a given internet layer address, typically an IPv4 address.

The Address Resolution Protocol is a request-response protocol. Its messages are directly encapsulated by a link layer protocol. It is communicated within the boundaries of a single network, never routed across internetworking nodes. [9]

### IGMP

The Internet Group Management Protocol (IGMP) is a communications protocol used by hosts and adjacent routers on IPv4 networks to establish multicast group memberships. IGMP is an integral part of IP multicast and allows the network to direct multicast transmissions only to hosts that have requested them.

IGMP can be used for one-to-many networking applications such as online streaming video and gaming, and allows more efficient use of resources when supporting these types of applications.

IGMP is used on IPv4 networks. [10]

### NDP

The Neighbor Discovery Protocol (NDP), or simply Neighbor Discovery (ND), is a protocol of the Internet protocol suite used with Internet Protocol Version 6 (IPv6). It operates at the link layer of the Internet model, and is responsible for gathering various information required for network communication, including the configuration of local connections and the domain name servers and gateways.

The protocol defines five ICMPv6 packet types to perform functions for IPv6 similar to the Address Resolution Protocol (ARP) and Internet Control Message Protocol (ICMP) Router Discovery and Router Redirect protocols for IPv4. [11]

### MLD

Multicast Listener Discovery (MLD) is a component of the Internet Protocol Version 6 (IPv6) suite. MLD is used by IPv6 routers for discovering multicast listeners on a directly attached link, much like Internet Group Management Protocol (IGMP) is used in IPv4. The protocol is embedded in ICMPv6 instead of using a separate protocol. [12]

## Testing

Testing was done on my WSL subsystem and reference NIX machine. Crosschecking with Wireshark [13] was also used, to confirm the correctness of my implementation of the packet sniffer.

### TCP Testing

For TCP testing, ```tcpreplay``` was used with a DNS Zone Transfer packet capture [14] which utilizes TCP on port 53.

```utf-8
sudo tcpreplay -t -i lo dns-zone-transfer-axfr.cap
```

```utf-8
sudo ./ipk-sniffer -i lo --tcp -p 53 -n 2
timestamp: 2023-4-16T14:37:26.744+02:00
src MAC: 08:00:27:97:3f:45
dst MAC: 08:00:27:38:db:ed
frame length: 62
src IP: 1.1.1.2
dst IP: 1.1.1.1
src port: 1042
dst port: 53

0x0000: 08 00 27 38 db ed 08 00 27 97 3f 45 08 00 45 00 ..'8.... '.?E..E.
0x0010: 00 30 00 ea 40 00 80 06 f5 d9 01 01 01 02 01 01 .0..@... ........
0x0020: 01 01 04 12 00 35 d1 f8 c1 16 00 00 00 00 70 02 .....5.. ......p.
0x0030: fa f0 ec d3 00 00 02 04 05 b4 01 01 04 02       ........ ......
timestamp: 2023-4-16T14:37:26.744+02:00
src MAC: 08:00:27:38:db:ed
dst MAC: 08:00:27:97:3f:45
frame length: 62
src IP: 1.1.1.1
dst IP: 1.1.1.2
src port: 53
dst port: 1042

0x0000: 08 00 27 97 3f 45 08 00 27 38 db ed 08 00 45 00 ..'.?E.. '8....E.
0x0010: 00 30 0d 54 00 00 80 06 29 70 01 01 01 01 01 01 .0.T.... )p......
0x0020: 01 02 00 35 04 12 5f f5 a8 bc d1 f8 c1 17 70 12 ...5.._. ......p.
0x0030: ff ff e1 1d 00 00 02 04 03 98 01 01 04 02       ........ ......
```

### UDP Testing

For UDP testing, ```ping``` command was used to capture the DNS communication on port 53.

```utf-8
ping google.com
```

```utf-8
sudo ./ipk-sniffer -i eth0 --udp -p 53 -n 2
timestamp: 2023-4-16T14:31:39.750+02:00
src MAC: 00:15:5d:1d:67:eb
dst MAC: 00:15:5d:1a:af:a4
frame length: 87
src IP: 172.20.75.172
dst IP: 172.20.64.1
src port: 35087
dst port: 53

0x0000: 00 15 5d 1a af a4 00 15 5d 1d 67 eb 08 00 45 00 ..]..... ].g...E.
0x0010: 00 49 27 97 40 00 40 11 2f 37 ac 14 4b ac ac 14 .I'.@.@. /7..K...
0x0020: 40 01 89 0f 00 35 00 35 e4 1c e8 d9 01 00 00 01 @....5.5 ........
0x0030: 00 00 00 00 00 00 03 31 34 32 02 33 36 03 32 35 .......1 42.36.25
0x0040: 31 03 31 34 32 07 69 6e 2d 61 64 64 72 04 61 72 1.142.in -addr.ar
0x0050: 70 61 00 00 0c 00 01                            pa.....
timestamp: 2023-4-16T14:31:39.750+02:00
src MAC: 00:15:5d:1a:af:a4
dst MAC: 00:15:5d:1d:67:eb
frame length: 153
src IP: 172.20.64.1
dst IP: 172.20.75.172
src port: 53
dst port: 35087

0x0000: 00 15 5d 1d 67 eb 00 15 5d 1a af a4 08 00 45 00 ..].g... ].....E.
0x0010: 00 8b ff 28 00 00 80 11 57 63 ac 14 40 01 ac 14 ...(.... Wc..@...
0x0020: 4b ac 00 35 89 0f 00 77 69 6b e8 d9 81 00 00 01 K..5...w ik......
0x0030: 00 01 00 00 00 00 03 31 34 32 02 33 36 03 32 35 .......1 42.36.25
0x0040: 31 03 31 34 32 07 69 6e 2d 61 64 64 72 04 61 72 1.142.in -addr.ar
0x0050: 70 61 00 00 0c 00 01 03 31 34 32 02 33 36 03 32 pa...... 142.36.2
0x0060: 35 31 03 31 34 32 07 69 6e 2d 61 64 64 72 04 61 51.142.i n-addr.a
0x0070: 72 70 61 00 00 0c 00 01 00 00 00 00 00 1b 0f 70 rpa..... .......p
0x0080: 72 67 30 33 73 31 32 2d 69 6e 2d 66 31 34 05 31 rg03s12- in-f14.1
0x0090: 65 31 30 30 03 6e 65 74 00                      e100.net .
```

### ICMPv4 Testing

For ICMP testing, ```ping``` command was used and for testing ICMPv6 ```tcpreplay``` was used with ICMPv6 packet capture file. [15]

```utf-8
ping merlin.fit.vutbr.cz
```

```utf-8
sudo ./ipk-sniffer -i eth0 --icmp4 -n 2
timestamp: 2023-4-16T09:05:53.484+02:00
src MAC: 00:15:5d:1d:67:eb
dst MAC: 00:15:5d:1a:af:a4
frame length: 98
src IP: 172.20.75.172
dst IP: 147.229.176.19

0x0000: 00 15 5d 1a af a4 00 15 5d 1d 67 eb 08 00 45 00 ..]..... ].g...E.
0x0010: 00 54 af db 40 00 40 01 4f 14 ac 14 4b ac 93 e5 .T..@.@. O...K...
0x0020: b0 13 08 00 da c7 e1 04 00 01 51 9e 3b 64 00 00 ........ ..Q.;d..
0x0030: 00 00 e9 5c 07 00 00 00 00 00 10 11 12 13 14 15 ...\.... ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
0x0060: 36 37                                           67
timestamp: 2023-4-16T09:05:53.594+02:00
src MAC: 00:15:5d:1a:af:a4
dst MAC: 00:15:5d:1d:67:eb
frame length: 98
src IP: 147.229.176.19
dst IP: 172.20.75.172

0x0000: 00 15 5d 1d 67 eb 00 15 5d 1a af a4 08 00 45 00 ..].g... ].....E.
0x0010: 00 54 62 0e 00 00 3c 01 e0 e1 93 e5 b0 13 ac 14 .Tb...<. ........
0x0020: 4b ac 00 00 e2 c7 e1 04 00 01 51 9e 3b 64 00 00 K....... ..Q.;d..
0x0030: 00 00 e9 5c 07 00 00 00 00 00 10 11 12 13 14 15 ...\.... ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
0x0060: 36 37                                           67
```

```utf-8
ping google.com
```

```utf-8
sudo ./ipk-sniffer -i eth0 --icmp4 -n 2
timestamp: 2023-4-16T09:07:20.482+02:00
src MAC: 00:15:5d:1d:67:eb
dst MAC: 00:15:5d:1a:af:a4
frame length: 98
src IP: 172.20.75.172
dst IP: 142.251.37.110

0x0000: 00 15 5d 1a af a4 00 15 5d 1d 67 eb 08 00 45 00 ..]..... ].g...E.
0x0010: 00 54 1f dc 40 00 40 01 6e a3 ac 14 4b ac 8e fb .T..@.@. n...K...
0x0020: 25 6e 08 00 e1 3a bc 2c 00 01 a8 9e 3b 64 00 00 %n...:., ....;d..
0x0030: 00 00 b1 c1 06 00 00 00 00 00 10 11 12 13 14 15 ........ ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
0x0060: 36 37                                           67
timestamp: 2023-4-16T09:07:20.482+02:00
src MAC: 00:15:5d:1a:af:a4
dst MAC: 00:15:5d:1d:67:eb
frame length: 98
src IP: 142.251.37.110
dst IP: 172.20.75.172

0x0000: 00 15 5d 1d 67 eb 00 15 5d 1a af a4 08 00 45 00 ..].g... ].....E.
0x0010: 00 54 00 00 00 00 77 01 97 7f 8e fb 25 6e ac 14 .T....w. ....%n..
0x0020: 4b ac 00 00 e9 3a bc 2c 00 01 a8 9e 3b 64 00 00 K....:., ....;d..
0x0030: 00 00 b1 c1 06 00 00 00 00 00 10 11 12 13 14 15 ........ ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
0x0060: 36 37                                           67
```

```utf-8
ping vut.cz
```

```utf-8
sudo ./ipk-sniffer -i eth0 --icmp4 -n 2
timestamp: 2023-4-16T09:09:56.365+02:00
src MAC: 00:15:5d:1d:67:eb
dst MAC: 00:15:5d:1a:af:a4
frame length: 98
src IP: 172.20.75.172
dst IP: 147.229.2.90

0x0000: 00 15 5d 1a af a4 00 15 5d 1d 67 eb 08 00 45 00 ..]..... ].g...E.
0x0010: 00 54 49 6e 40 00 40 01 63 3b ac 14 4b ac 93 e5 .TIn@.@. c;..K...
0x0020: 02 5a 08 00 3c c8 46 2c 00 01 44 9f 3b 64 00 00 .Z..<.F, ..D.;d..
0x0030: 00 00 32 34 04 00 00 00 00 00 10 11 12 13 14 15 ..24.... ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
0x0060: 36 37                                           67
timestamp: 2023-4-16T09:09:56.365+02:00
src MAC: 00:15:5d:1a:af:a4
dst MAC: 00:15:5d:1d:67:eb
frame length: 98
src IP: 147.229.2.90
dst IP: 172.20.75.172

0x0000: 00 15 5d 1d 67 eb 00 15 5d 1a af a4 08 00 45 00 ..].g... ].....E.
0x0010: 00 54 71 82 00 00 3c 01 7f 27 93 e5 02 5a ac 14 .Tq...<. .'...Z..
0x0020: 4b ac 00 00 44 c8 46 2c 00 01 44 9f 3b 64 00 00 K...D.F, ..D.;d..
0x0030: 00 00 32 34 04 00 00 00 00 00 10 11 12 13 14 15 ..24.... ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
0x0060: 36 37                                           67
```

### ICMPv6 Testing

```utf-8
sudo tcpreplay -t -i lo ICMPv6_echos.cap
```

```utf-8
sudo ./ipk-sniffer -i lo --icmp6 -n 2
timestamp: 2023-4-16T09:51:12.674+02:00
src MAC: c2:00:51:fa:00:00
dst MAC: c2:01:51:fa:00:00
frame length: 114
src IP: 2001:db8:0:12::1
dst IP: 2001:db8:0:12::2

0x0000: c2 01 51 fa 00 00 c2 00 51 fa 00 00 86 dd 60 00 ..Q..... Q.....`.
0x0010: 00 00 00 3c 3a 40 20 01 0d b8 00 00 00 12 00 00 ...<:@ . ........
0x0020: 00 00 00 00 00 01 20 01 0d b8 00 00 00 12 00 00 ...... . ........
0x0030: 00 00 00 00 00 02 80 00 86 3c 11 0d 00 00 00 01 ........ .<......
0x0040: 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 ........ ........
0x0050: 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 ........ ...... !
0x0060: 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 "#$%&'() *+,-./01
0x0070: 32 33                                           23
timestamp: 2023-4-16T09:51:12.674+02:00
src MAC: c2:01:51:fa:00:00
dst MAC: c2:00:51:fa:00:00
frame length: 114
src IP: 2001:db8:0:12::2
dst IP: 2001:db8:0:12::1

0x0000: c2 00 51 fa 00 00 c2 01 51 fa 00 00 86 dd 60 00 ..Q..... Q.....`.
0x0010: 00 00 00 3c 3a 40 20 01 0d b8 00 00 00 12 00 00 ...<:@ . ........
0x0020: 00 00 00 00 00 02 20 01 0d b8 00 00 00 12 00 00 ...... . ........
0x0030: 00 00 00 00 00 01 81 00 85 3c 11 0d 00 00 00 01 ........ .<......
0x0040: 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 ........ ........
0x0050: 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 ........ ...... !
0x0060: 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 "#$%&'() *+,-./01
0x0070: 32 33                                           23
```

### ARP Testing

For ARP testing, ```tcpreplay``` was used with corresponding packet capture file. [16]

```utf-8
sudo tcpreplay -t -i lo arp_pcap.pcapng.cap
```

```utf-8
sudo ./ipk-sniffer -i lo --arp -n 2
timestamp: 2023-4-16T09:58:41.404+02:00
src MAC: c4:01:32:58:00:00
dst MAC: c4:02:32:6b:00:00
frame length: 60
src IP: 10:0:0:1
dst IP: 10:0:0:2

0x0000: c4 02 32 6b 00 00 c4 01 32 58 00 00 08 06 00 01 ..2k.... 2X......
0x0010: 08 00 06 04 00 01 c4 01 32 58 00 00 0a 00 00 01 ........ 2X......
0x0020: c4 02 32 6b 00 00 0a 00 00 02 00 00 00 00 00 00 ..2k.... ........
0x0030: 00 00 00 00 00 00 00 00 00 00 00 00             ........ ....
timestamp: 2023-4-16T09:58:41.404+02:00
src MAC: c4:02:32:6b:00:00
dst MAC: c4:01:32:58:00:00
frame length: 60
src IP: 10:0:0:2
dst IP: 10:0:0:1

0x0000: c4 01 32 58 00 00 c4 02 32 6b 00 00 08 06 00 01 ..2X.... 2k......
0x0010: 08 00 06 04 00 02 c4 02 32 6b 00 00 0a 00 00 02 ........ 2k......
0x0020: c4 01 32 58 00 00 0a 00 00 01 00 00 00 00 00 00 ..2X.... ........
0x0030: 00 00 00 00 00 00 00 00 00 00 00 00             ........ ....
```

### IGMP Testing

For IGMP testing, ```tcpreplay``` was used with corresponding packet capture file. [17]

```utf-8
sudo tcpreplay -t -i lo IGMP_V2.cap
```

```utf-8
sudo ./ipk-sniffer -i lo --igmp -n 2
timestamp: 2023-4-16T10:03:18.854+02:00
src MAC: 00:1b:11:10:26:11
dst MAC: 01:00:5e:00:00:01
frame length: 60
src IP: 192.168.1.2
dst IP: 224.0.0.1

0x0000: 01 00 5e 00 00 01 00 1b 11 10 26 11 08 00 45 00 ..^..... ..&...E.
0x0010: 00 1c 65 51 00 00 01 02 b2 e3 c0 a8 01 02 e0 00 ..eQ.... ........
0x0020: 00 01 11 64 ee 9b 00 00 00 00 00 00 00 00 00 00 ...d.... ........
0x0030: 00 00 00 00 00 00 00 00 00 00 00 00             ........ ....
timestamp: 2023-4-16T10:03:18.854+02:00
src MAC: 00:1c:23:aa:be:ad
dst MAC: 01:00:5e:7f:ff:fa
frame length: 46
src IP: 192.168.1.64
dst IP: 239.255.255.250

0x0000: 01 00 5e 7f ff fa 00 1c 23 aa be ad 08 00 46 00 ..^..... #.....F.
0x0010: 00 20 8c 62 00 00 01 02 e6 92 c0 a8 01 40 ef ff . .b.... .....@..
0x0020: ff fa 94 04 00 00 16 00 fa 04 ef ff ff fa       ........ ......
```

### NDP Testing

For NDP testing, ```tcpreplay``` was used with corresponding packet capture file. [18]

```utf-8
sudo tcpreplay -t -i lo IPv6_NDP.cap
```

```utf-8
sudo ./ipk-sniffer -i lo --ndp -n 2
timestamp: 2023-4-16T11:31:08.555+02:00
src MAC: c2:00:54:f5:00:00
dst MAC: 33:33:ff:f5:00:00
frame length: 78
src IP: ::
dst IP: ff02::1:fff5:0

0x0000: 33 33 ff f5 00 00 c2 00 54 f5 00 00 86 dd 6e 00 33...... T.....n.
0x0010: 00 00 00 18 3a ff 00 00 00 00 00 00 00 00 00 00 ....:... ........
0x0020: 00 00 00 00 00 00 ff 02 00 00 00 00 00 00 00 00 ........ ........
0x0030: 00 01 ff f5 00 00 87 00 67 3c 00 00 00 00 fe 80 ........ g<......
0x0040: 00 00 00 00 00 00 c0 00 54 ff fe f5 00 00       ........ T.....
timestamp: 2023-4-16T11:31:08.555+02:00
src MAC: c2:00:54:f5:00:00
dst MAC: 33:33:00:00:00:01
frame length: 86
src IP: fe80::c000:54ff:fef5:0
dst IP: ff02::1

0x0000: 33 33 00 00 00 01 c2 00 54 f5 00 00 86 dd 6e 00 33...... T.....n.
0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 c0 00 ... :... ........
0x0020: 54 ff fe f5 00 00 ff 02 00 00 00 00 00 00 00 00 T....... ........
0x0030: 00 00 00 00 00 01 88 00 9a bb a0 00 00 00 fe 80 ........ ........
0x0040: 00 00 00 00 00 00 c0 00 54 ff fe f5 00 00 02 01 ........ T.......
0x0050: c2 00 54 f5 00 00                               ..T...
```

### MLD Testing

For MLD testing, a simple python script was used, that sends 1 MLD packet.

```python
from scapy.all import *

send(IPv6(src="2001:db8::1", dst="ff02::16")/ICMPv6MLQuery())
```

```utf-8
sudo python3 mld.py
```

```utf-8
sudo ./ipk-sniffer -i eth0 --mld -n 1
timestamp: 2023-4-16T15:25:26.754+02:00
src MAC: 00:15:5d:1d:67:eb
dst MAC: 33:33:00:00:00:16
frame length: 78
src IP: 2001:db8::1
dst IP: ff02::16

0x0000: 33 33 00 00 00 16 00 15 5d 1d 67 eb 86 dd 60 00 33...... ].g...`.
0x0010: 00 00 00 18 3a 01 20 01 0d b8 00 00 00 00 00 00 ....:. . ........
0x0020: 00 00 00 00 00 01 ff 02 00 00 00 00 00 00 00 00 ........ ........
0x0030: 00 00 00 00 00 16 82 00 29 ca 27 10 00 00 00 00 ........ ).'.....
0x0040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00       ........ ......
```

## Bibliography

[1] <https://www.tcpdump.org/>

[2] <https://en.wikipedia.org/wiki/Ethernet_frame>

[3] <https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure>

[4] <https://en.wikipedia.org/wiki/IPv6_packet>

[5] <https://en.wikipedia.org/wiki/Transmission_Control_Protocol>

[6] <https://en.wikipedia.org/wiki/User_Datagram_Protocol>

[7] <https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>

[8] <https://en.wikipedia.org/wiki/ICMPv6>

[9] <https://en.wikipedia.org/wiki/Address_Resolution_Protocol>

[10] <https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol>

[11] <https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol>

[12] <https://en.wikipedia.org/wiki/Multicast_Listener_Discovery>

[13] <https://www.wireshark.org/>

[14] <https://packetlife.net/media/captures/dns-zone-transfer-axfr.cap>

[15] <https://packetlife.net/media/captures/ICMPv6_echos.cap>

[16] <https://packetlife.net/media/captures/arp_pcap.pcapng.cap>

[17] <https://packetlife.net/media/captures/IGMP_V2.cap>

[18] <https://packetlife.net/media/captures/IPv6_NDP.cap>
