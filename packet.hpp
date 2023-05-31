/**
 * @file ipk-sniffer.cpp
 * @author Matúš Ďurica (xduric06)
 *
 */
#ifndef PACKET_HPP
#define PACKET_HPP

#include "ipk-sniffer.hpp"

#define ADD_TCP \
    filter += "tcp";

#define ADD_TCP_PORT(int) \
    filter += "(tcp and port " + to_string(int) + ")";

#define ADD_UDP           \
    if (filter != "")     \
        filter += " or "; \
    filter += "udp";

#define ADD_UDP_PORT(int) \
    if (filter != "")     \
        filter += " or "; \
    filter += "(udp and port " + to_string(int) + ")";

#define ADD_ICMP4         \
    if (filter != "")     \
        filter += " or "; \
    filter += "icmp";

#define ADD_ICMP6         \
    if (filter != "")     \
        filter += " or "; \
    filter += "icmp6";

#define ADD_ARP           \
    if (filter != "")     \
        filter += " or "; \
    filter += "arp";

#define ADD_NDP           \
    if (filter != "")     \
        filter += " or "; \
    filter += "(icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136))";

#define ADD_IGMP          \
    if (filter != "")     \
        filter += " or "; \
    filter += "igmp";

#define ADD_MLD           \
    if (filter != "")     \
        filter += " or "; \
    filter += "(icmp6 and (ip6[40] == 130 or ip6[40] == 131 or ip6[40] == 132 or ip6[40] == 143))";

typedef struct
{
    string src_mac;     // Source MAC address
    string dst_mac;     // Destination MAC address
    int frame_length;   // Frame length in bytes
    string src_ip_addr; // Source IP address
    string dst_ip_addr; // Destination IP address
    int src_port_num;   // Source port number
    int dst_port_num;   // Source port number
} processed_data_t;

string create_filter(args_t *);

void pcap_process_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

void print_time();

void print_out(processed_data_t, const u_char *);

void dump_payload(processed_data_t, const u_char *);

void print_hex_ascii_line(const u_char *, int, int);

string parse_mac_addr(u_char *);

string parse_ip_addr(u_char *);

string parse_ipv6_addr(struct in6_addr);

#endif // PACKET_HPP