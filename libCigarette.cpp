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

#include <cstdio>
#include <cstdlib>
#include <string>
#include "libCigarette.h"

std::string ether_type_decode(int start)
{
	// Maggiore o uguale di 1536(0x0600) per Ethernet v2, minore per versione

	if(start >= ETHER_V2_CODE)
	{
		switch(start)
		{
			case (ETHER_TYPE_IPV4):
				return "IPv4";
			case (ETHER_TYPE_ARP):
				return "ARP";
			case (ETHER_TYPE_IPV6):
				return "IPv6";
			case (ETHER_TYPE_PPP):
				return "PPP";
			case (ETHER_TYPE_IEEE802):
				return "IEEE 802.1Q";
			default:
				return "UNDEFINED";
		}
	}
	else return "Ethernet IEEE 802.3";
}

std::string ipv4_type_decode(int start)
{
	switch(start)
	{
		case (IPV4_TYPE_TCP):
			return "TCP";
		case (IPV4_TYPE_UDP):
			return "UDP";
		default:
			return "UNDEFINED";
	}
}
