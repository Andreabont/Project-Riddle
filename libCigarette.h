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

#define IPV4_TYPE_TCP		0x06
#define IPV4_TYPE_UDP		0x11

std::string ether_type_decode(int start);
std::string ipv4_type_decode(int start);

#endif //LIBCIGARETTE_H
