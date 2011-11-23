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

#ifndef LIBCIGARETTE_H
#define LIBCIGARETTE_H

#include <string>

#define ETHER_TYPE_IPV4		0x0800
#define ETHER_TYPE_IPV6		0x86DD
#define ETHER_TYPE_ARP		0x0806
#define ETHER_TYPE_IEEE802	0x8100

struct header_ethernet
{
	std::string mac_dst;
	std::string mac_src;
	int ether_type;
};

header_ethernet parseEthernet(std::string start, int len);
std::string ether_type_decode(int start);

#endif //LIBCIGARETTE_H
