/**
 * @file ipk-sniffer.cpp
 * @author Matúš Ďurica (xduric06)
 *
 */
#ifndef IPK_SNIFFER_HPP
#define IPK_SNIFFER_HPP

#include <string>
#include <pcap.h>

using namespace std;

inline char errbuf[PCAP_ERRBUF_SIZE] = {0};

inline pcap_t *dev_handle;

typedef struct
{
    bool print_intf; // Interface printing flag
    string interf;   // Interface name string
    bool tcp;        // TCP sniffing flag
    bool udp;        // UDP sniffing flag
    int port_num;    // Port number where we sniff
    bool icmp4;      // ICMP4 sniffing flag
    bool icmp6;      // ICMP6 sniffing flag
    bool arp;        // ARP sniffing flag
    bool ndp;        // NDP sniffing flag
    bool igmp;       // IGMP sniffing flag
    bool mld;        // MLD sniffing flag
    int num;         // Number of sniffed packets
} args_t;

#endif // IPK_SNIFFER_HPP
