/**
 * @file ipk-sniffer.cpp
 * @author Matúš Ďurica (xduric06)
 *
 */
#include <iostream>
#include <chrono>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include <netinet/ip6.h>

#include "packet.hpp"
#include "utils.hpp"

using namespace std::chrono;

/**
 * @brief Create a filter string
 *
 * @param args Command-line argument structure
 * @return string Filter string
 */
string create_filter(args_t *args)
{
    string filter = "";
    if (args->port_num == -1)
    {
        if (args->tcp)
            ADD_TCP
        if (args->udp)
        {
            ADD_UDP
        }
    }
    else
    {
        if (args->tcp)
            ADD_TCP_PORT(args->port_num)
        if (args->udp)
        {
            ADD_UDP_PORT(args->port_num)
        }
    }

    if (args->icmp4)
    {
        ADD_ICMP4
    }
    if (args->icmp6)
    {
        ADD_ICMP6
    }
    if (args->arp)
    {
        ADD_ARP
    }
    if (args->ndp)
    {
        ADD_NDP
    }
    if (args->igmp)
    {
        ADD_IGMP
    }
    if (args->mld)
    {
        ADD_MLD
    }
    return filter;
}

/**
 * @brief Handler function for pcap_loop
 *
 * @param foo Placeholder
 * @param pckt_header Packet header
 * @param packet Packet
 */
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

/**
 * @brief Prints timestamp of packet in RFC3339 format
 *
 */
void print_time()
{
    // Taken from https://gist.github.com/jedisct1/b7812ae9b4850e0053a21c922ed3e9dc under CC0 license
    time_t now = time(NULL);
    struct tm *tm;
    int off_sign, off;

    // Milliseconds taken from https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono
    const auto now_ms = time_point_cast<milliseconds>(system_clock::now());
    const auto now_s = time_point_cast<seconds>(now_ms);
    const auto millis = now_ms - now_s;

    if ((tm = localtime(&now)) == NULL)
    {
        return;
    }
    off_sign = '+';
    off = (int)tm->tm_gmtoff;
    if (tm->tm_gmtoff < 0)
    {
        off_sign = '-';
        off = -off;
    }
    printf("%d-%d-%dT%02d:%02d:%02d.%03ld%c%02d:%02d",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec, millis.count(),
           off_sign, off / 3600, off % 3600);
    cout << endl;
}

/**
 * @brief Prints sniffed data
 *
 * @param data Data structure
 * @param payload Payload
 */
void print_out(processed_data_t data, const u_char *payload)
{
    cout << "timestamp: ";
    print_time();
    cout << "src MAC: " << data.src_mac << endl;
    cout << "dst MAC: " << data.dst_mac << endl;
    cout << "frame length: " << data.frame_length << endl;
    cout << "src IP: " << data.src_ip_addr << endl;
    cout << "dst IP: " << data.dst_ip_addr << endl;
    if (data.src_port_num != -1)
        cout << "src port: " << data.src_port_num << endl;
    if (data.dst_port_num != -1)
        cout << "dst port: " << data.dst_port_num << endl;
    cout << endl;
    dump_payload(data, payload);
}

/**
 * @brief Dumps payload in hex and ascii
 *
 * @param data Data structure
 * @param payload Payload
 */
void dump_payload(processed_data_t data, const u_char *payload)
{
    /* taken from https://www.tcpdump.org/other/sniffex.c
    ****************************************************************************
    *
    * This software is a modification of Tim Carstens' "sniffer.c"
    * demonstration source code, released as follows:
    *
    * sniffer.c
    * Copyright (c) 2002 Tim Carstens
    * 2002-01-07
    * Demonstration of using libpcap
    * timcarst -at- yahoo -dot- com
    *
    * "sniffer.c" is distributed under these terms:
    *
    * Redistribution and use in source and binary forms, with or without
    * modification, are permitted provided that the following conditions
    * are met:
    * 1. Redistributions of source code must retain the above copyright
    *    notice, this list of conditions and the following disclaimer.
    * 2. Redistributions in binary form must reproduce the above copyright
    *    notice, this list of conditions and the following disclaimer in the
    *    documentation and/or other materials provided with the distribution.
    * 4. The name "Tim Carstens" may not be used to endorse or promote
    *    products derived from this software without prior written permission
    *
    * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
    * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
    * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    * SUCH DAMAGE.
    * <end of "sniffer.c" terms>
    *
    * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
    * covered by the following terms:
    *
    * Redistribution and use in source and binary forms, with or without
    * modification, are permitted provided that the following conditions
    * are met:
    * 1. Because this is a derivative work, you must comply with the "sniffer.c"
    *    terms reproduced above.
    * 2. Redistributions of source code must retain the Tcpdump Group copyright
    *    notice at the top of this source file, this list of conditions and the
    *    following disclaimer.
    * 3. Redistributions in binary form must reproduce the above copyright
    *    notice, this list of conditions and the following disclaimer in the
    *    documentation and/or other materials provided with the distribution.
    * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
    *    products derived from this software without prior written permission.
    *
    * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
    * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
    * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
    * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
    * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
    * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
    * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
    * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
    * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
    * REPAIR OR CORRECTION.
    *
    * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
    * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
    * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
    * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
    * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
    * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
    * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
    * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
    * POSSIBILITY OF SUCH DAMAGES.
    * <end of "sniffex.c" terms>
    *
    ****************************************************************************
    */
    int len_rem = data.frame_length;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *ch = payload;

    if (data.frame_length <= 0)
        return;
    /* data fits on one line */
    if (data.frame_length <= line_width)
    {
        print_hex_ascii_line(ch, data.frame_length, offset);
        return;
    }
    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

/**
 * @brief Prints one line with hex and ascii data
 *
 * @param payload Payload
 * @param len Length of payload
 * @param offset Offset
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    /* taken from https://www.tcpdump.org/other/sniffex.c
    ****************************************************************************
    *
    * This software is a modification of Tim Carstens' "sniffer.c"
    * demonstration source code, released as follows:
    *
    * sniffer.c
    * Copyright (c) 2002 Tim Carstens
    * 2002-01-07
    * Demonstration of using libpcap
    * timcarst -at- yahoo -dot- com
    *
    * "sniffer.c" is distributed under these terms:
    *
    * Redistribution and use in source and binary forms, with or without
    * modification, are permitted provided that the following conditions
    * are met:
    * 1. Redistributions of source code must retain the above copyright
    *    notice, this list of conditions and the following disclaimer.
    * 2. Redistributions in binary form must reproduce the above copyright
    *    notice, this list of conditions and the following disclaimer in the
    *    documentation and/or other materials provided with the distribution.
    * 4. The name "Tim Carstens" may not be used to endorse or promote
    *    products derived from this software without prior written permission
    *
    * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
    * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
    * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    * SUCH DAMAGE.
    * <end of "sniffer.c" terms>
    *
    * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
    * covered by the following terms:
    *
    * Redistribution and use in source and binary forms, with or without
    * modification, are permitted provided that the following conditions
    * are met:
    * 1. Because this is a derivative work, you must comply with the "sniffer.c"
    *    terms reproduced above.
    * 2. Redistributions of source code must retain the Tcpdump Group copyright
    *    notice at the top of this source file, this list of conditions and the
    *    following disclaimer.
    * 3. Redistributions in binary form must reproduce the above copyright
    *    notice, this list of conditions and the following disclaimer in the
    *    documentation and/or other materials provided with the distribution.
    * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
    *    products derived from this software without prior written permission.
    *
    * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
    * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
    * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
    * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
    * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
    * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
    * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
    * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
    * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
    * REPAIR OR CORRECTION.
    *
    * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
    * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
    * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
    * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
    * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
    * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
    * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
    * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
    * POSSIBILITY OF SUCH DAMAGES.
    * <end of "sniffex.c" terms>
    *
    ****************************************************************************
    */
    int i;
    int gap;
    const u_char *ch;
    /* offset */
    printf("0x%04x: ", offset);
    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
    }
    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
            cout << "   ";
    }
    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (i == 8)
            cout << " ";
        if (isprint(*ch))
            cout << *ch;
        else
            cout << ".";
        ch++;
    }
    cout << endl;
}

/**
 * @brief Parses MAC address from input
 *
 * @param addr Input
 * @return string Parsed MAC address
 */
string parse_mac_addr(u_char *addr)
{
    char tmp[18];
    sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return tmp;
}

/**
 * @brief Parses IP address from input
 *
 * @param addr Input
 * @return string Parsed IP address
 */
string parse_ip_addr(u_char *addr)
{
    char tmp[16];
    sprintf(tmp, "%d:%d:%d:%d", addr[0], addr[1], addr[2], addr[3]);
    return tmp;
}

/**
 * @brief Parses IPv6 address from input
 *
 * @param addr Input
 * @return string Parsed IP address
 */
string parse_ipv6_addr(struct in6_addr addr)
{
    char tmp[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(addr), tmp, INET6_ADDRSTRLEN);
    return tmp;
}