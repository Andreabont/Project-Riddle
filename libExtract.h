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

#define ETHER_V2_CODE		0x0600
#define ETHER_TYPE_IPV4		0x0800
#define ETHER_TYPE_ARP		0x0806
#define ETHER_TYPE_IEEE802	0x8100
#define ETHER_TYPE_IPV6		0x86DD
#define ETHER_TYPE_PPP		0x880B

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

std::string ether_type_decode(int start);
std::string print_mac_address(mac_address mac);
std::string print_ipv4_address(ipv4_address ip);
mac_address extract_mac_address(std::string packet, int start);
ipv4_address extract_ipv4_address(std::string packet, int start);

#endif //LIBEXTRACT_H