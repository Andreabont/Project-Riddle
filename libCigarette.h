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
#include "libExtract.h"

struct header_ethernet
{
	mac_address mac_dst;
	mac_address mac_src;
	int ether_type;
};

struct header_arp
{
	int hardware_type;
	int protocol_type;
	int opcode;
	mac_address mac_dst;
	mac_address mac_src;
	ipv4_address ip_dst;
	ipv4_address ip_src;
};

header_ethernet parseEthernet(std::string start);
header_arp parseArp(std::string start);

#endif //LIBCIGARETTE_H
