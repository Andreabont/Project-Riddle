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

#define ETHER_V2_CODE		0x0600
#define ETHER_TYPE_IPV4		0x0800
#define ETHER_TYPE_ARP		0x0806
#define ETHER_TYPE_IEEE802	0x8100
#define ETHER_TYPE_IPV6		0x86DD
#define ETHER_TYPE_PPP		0x880B

struct header_ethernet
{
	std::string mac_dst;
	std::string mac_src;
	int ether_type;
};

struct header_arp
{
	int hardware_type;
	int protocol_type;
	int opcode;
	std::string mac_dst;
	std::string mac_src;
	std::string ip_dst;
	std::string ip_src;
};

header_ethernet parseEthernet(std::string start);
header_arp parseArp(std::string start);
std::string ether_type_decode(int start);

#endif //LIBCIGARETTE_H
