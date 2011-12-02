//============================================================================
// Name        : Riddle
// Author      : Andrea Bontempi
// Version     : 0.1
// Copyright   : GNU GPL3
// Description : Network Sniffer
//
// Special Thanks to fede.tft for the big help :-)
//
//============================================================================

#ifndef LIBEXTRACT_H
#define LIBEXTRACT_H

#include <string>

struct mac_address
{
	short int byte[6];
};

struct ipv4_address
{
	short int byte[4];
};

struct ipv6_address
{
	int byte[8];
};

std::string print_mac_address(mac_address mac);
std::string print_ipv4_address(ipv4_address ip);
mac_address extract_mac_address(std::string packet, int start);
ipv4_address extract_ipv4_address(std::string packet, int start);

#endif //LIBEXTRACT_H