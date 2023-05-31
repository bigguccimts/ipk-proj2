/**
 * @file ipk-sniffer.cpp
 * @author Matúš Ďurica (xduric06)
 *
 */
#include <csignal>
#include <iostream>
#include <pcap.h>

#include "ipk-sniffer.hpp"
#include "utils.hpp"
#include "packet.hpp"

using namespace std;

int main(int argc, char **argv)
{
    args_t args = {
        false,
        "",
        false,
        false,
        -1,
        false,
        false,
        false,
        false,
        false,
        false,
        1};
    struct bpf_program packet_filter;
    bpf_u_int32 ip_addr, mask;

    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    parse_args(argc, argv, &args);

    if (args.print_intf)
    {
        print_ints();
        exit(EXIT_SUCCESS);
    }

    if (pcap_lookupnet(args.interf.c_str(), &ip_addr, &mask, errbuf) == -1)
    {
        ip_addr = 0;
        mask = 0;
        cerr << "Can not get mask for interface " << args.interf << endl;
    }

    if (!(dev_handle = pcap_open_live(args.interf.c_str(), BUFSIZ, 1, 100, errbuf)))
        print_err(errbuf, EXIT_FAILURE);

    if (pcap_datalink(dev_handle) != DLT_EN10MB)
    {
        pcap_close(dev_handle);
        print_err("Interface does not provide ethernet headers!", EXIT_FAILURE);
    }

    if (pcap_compile(dev_handle, &packet_filter, create_filter(&args).c_str(), 0, ip_addr) == -1)
    {
        pcap_close(dev_handle);
        print_err(pcap_geterr(dev_handle), EXIT_FAILURE);
    }

    if (pcap_setfilter(dev_handle, &packet_filter) == -1)
    {
        pcap_close(dev_handle);
        print_err(pcap_geterr(dev_handle), EXIT_FAILURE);
    }

    if (pcap_loop(dev_handle, args.num, pcap_process_handler, 0) == -1)
    {
        pcap_freecode(&packet_filter);
        pcap_close(dev_handle);
        print_err("Capture loop failed", EXIT_FAILURE);
    }

    pcap_freecode(&packet_filter);
    pcap_close(dev_handle);

    return EXIT_SUCCESS;
}
