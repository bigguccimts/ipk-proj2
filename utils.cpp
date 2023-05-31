/**
 * @file ipk-sniffer.cpp
 * @author Matúš Ďurica (xduric06)
 *
 */
#include <getopt.h>
#include <iostream>
#include <cstring>

#include "utils.hpp"

/**
 * @brief Handler for C-c
 *
 * @param sig
 */
void sigint_handler(int sig)
{
    (void)sig;
    pcap_breakloop(dev_handle);
}

/**
 * @brief Prints all interfaces
 *
 */
void print_ints()
{
    pcap_if_t *int_list_head, *int_list_item;

    if (pcap_findalldevs(&int_list_head, errbuf) == -1)
        print_err(errbuf, EXIT_FAILURE);

    for (int_list_item = int_list_head; int_list_item; int_list_item = int_list_item->next)
        cout << int_list_item->name << endl;

    pcap_freealldevs(int_list_head);
}

/**
 * @brief Parser command-line arguments
 *
 * @param argc Count of arguments
 * @param argv Array with command-line arguments
 * @param args Return structure
 */
void parse_args(int argc, char **argv, args_t *args)
{
    int opt;
    opterr = 0;
    struct option long_options[] =
        {
            {"interface", optional_argument, 0, 'i'},
            {"tcp", no_argument, 0, 't'},
            {"udp", no_argument, 0, 'u'},
            {"port", no_argument, 0, 'p'},
            {"icmp4", no_argument, 0, '4'},
            {"icmp6", no_argument, 0, '6'},
            {"arp", no_argument, 0, 'a'},
            {"ndp", no_argument, 0, 'd'},
            {"igmp", no_argument, 0, 'g'},
            {"mld", no_argument, 0, 'm'},
            {"num", optional_argument, 0, 'n'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}};
    string tmp;
    while ((opt = getopt_long(argc, argv, "i:p:n:tuh", long_options, NULL)) != -1)
    {
        const char *tmp_optarg = optarg;
        switch (opt)
        {
        case 'i':
            // Code for case 'i' inspired by https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
            if (!optarg && argv[optind] && argv[optind][0] != '-')
                tmp_optarg = argv[optind++];
            args->print_intf = true;
            if (tmp_optarg)
            {
                args->print_intf = false;
                args->interf = tmp_optarg;
            }
            break;
        case 't':
            args->tcp = true;
            break;
        case 'u':
            args->udp = true;
            break;
        case 'p':
            tmp = optarg;
            args->port_num = stoi(tmp);
            break;
        case '4':
            args->icmp4 = true;
            break;
        case '6':
            args->icmp6 = true;
            break;
        case 'a':
            args->arp = true;
            break;
        case 'd':
            args->ndp = true;
            break;
        case 'g':
            args->igmp = true;
            break;
        case 'm':
            args->mld = true;
            break;
        case 'n':
            tmp = optarg;
            args->num = stoi(tmp);
            break;
        case 'h':
            print_help();
            exit(EXIT_SUCCESS);
            break;
        case '?':
            if (optopt == 'i')
                args->print_intf = true;
            else if (optopt == 'n')
                args->num = 1;
            else
                print_err("Unknown argument!", EXIT_FAILURE);
            break;
        default:
            print_err("Unknown argument!", EXIT_FAILURE);
        }
    }
}

/**
 * @brief Prints error message and exits with error code
 *
 * @param msg Message string
 * @param ret_code Exit code
 */
void print_err(string msg, int exit_code)
{
    cerr << msg << endl;
    exit(exit_code);
}

/**
 * @brief Prints help
 * @todo For now just placeholder
 */
void print_help()
{
    cout << "Made by Matúš Ďurica (xduric06) VUT FIT v Brně 2023" << endl;
    cout << endl;
    cout << "\033[1mNAME\033[0m\n";
    cout << "ipk-sniffer\t - Packet sniffer" << endl;
    cout << endl;
    cout << "\033[1mSYNOPSIS\033[0m" << endl;
    cout << "./ipk-sniffer [-h | --help] [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}" << endl;
    cout << endl;
    cout << "-i | --interface interface - Specifies the interface where the sniffer will sniff packets" << endl;
    cout << "-t | --tcp                 - Only TCP segments will be displayed" << endl;
    cout << "-u | --udp                 - Only UDP datagrams will be displayed" << endl;
    cout << "-p port                    - If this parameter is not present, then no filtering by port number occurs." << endl;
    cout << "                             If yes, filtering by port will be applied to TCP and UDP " << endl;
    cout << "--icmp4                    - Only ICMPv4 packets will be displayed" << endl;
    cout << "--icmp6                    - Only ICMPv6 request/response packets will be displayed" << endl;
    cout << "--arp                      - Only ARP packets will be displayed" << endl;
    cout << "--ndp                      - Only NDP packets will be displayed" << endl;
    cout << "--igmp                     - Only IGMP packets will be displayed" << endl;
    cout << "--mld                      - Only MLD packets will be displayed" << endl;
    cout << "-n num                     - Specifies the number of packets to display, if not specified, application will display only 1 packet" << endl;
    cout << "-h | --help                - Prints help" << endl;
}