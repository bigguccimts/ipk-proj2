/**
 * @file ipk-sniffer.cpp
 * @author Matúš Ďurica (xduric06)
 *
 */
#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <pcap.h>

#include "ipk-sniffer.hpp"

void sigint_handler(int);

void print_ints();

void parse_args(int, char **, args_t *);

void print_err(string, int);

void print_help();

#endif // UTILS_HPP