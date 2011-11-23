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
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <ios>
#include "libCigarette.h"

header_ethernet parseEthernet(std::string start, int len)
{
	header_ethernet etherhead;

	int i;
	std::string temp;

	etherhead.mac_dst.reserve(17);
	etherhead.mac_src.reserve(17);
	temp.reserve(6);
	temp = "0x";
	
	for(i=0;i<=11;i++)	// MAC Dest
	{
		etherhead.mac_dst += start[i];
		if(i%2 != 0 && i != 11) etherhead.mac_dst += ':';
	}

	for(i=12;i<=23;i++)	// MAC Sorg
	{
		etherhead.mac_src += start[i];
		if(i%2 != 0 && i != 23) etherhead.mac_src += ':';
	}
	
	for(i=24;i<=27;i++)	// Next Protocol
	{
		temp += start[i];
		
	}
	
	std::stringstream convert ( temp );
	
	convert>> std::hex >> etherhead.ether_type;

	return etherhead;
}

std::string ether_type_decode(int start)
{	
	//TODO maggiore o uguale di 1536(0x0600) per Ethernet v2, minore per versione IEEE 802.3
		if (start == ETHER_TYPE_IPV4) return "IPv4 Packet";
		else if (start == ETHER_TYPE_IPV6) return "IPv6 Packet";
		else if (start == ETHER_TYPE_ARP) return "ARP Packet";
		else if (start == ETHER_TYPE_IEEE802) return "IEEE 802.1Q Frame";
		else return "undefined";
}