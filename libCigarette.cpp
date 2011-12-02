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
#include "libExtract.h"

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

header_ethernet parseEthernet(std::string start)
{
	header_ethernet etherhead;

	int i;
	std::string temp;
	temp.reserve(6);
	temp = "0x";

	etherhead.mac_dst = extract_mac_address(start, 0);

	etherhead.mac_src = extract_mac_address(start, 12);

	for(i=24;i<=27;i++)	// Next Protocol
	{
		temp += start[i];

	}

	std::stringstream convert ( temp );

	convert>> std::hex >> etherhead.protocol_type;

	return etherhead;
}

header_arp parseArp(std::string start)
{
	header_arp arphead;

	int i;
	std::string temp;
	temp.reserve(6);
	temp = "0x";

	for(i=32;i<=35;i++)	// Protocol Type
	{
		temp += start[i];
	}

	std::stringstream convert1 ( temp );

	convert1>> std::hex >> arphead.protocol_type;

	temp = "0x";

	for(i=40;i<=43;i++)	// Opcode
	{
		temp += start[i];
	}

	std::stringstream convert2 ( temp );

	convert2>> std::hex >> arphead.opcode;

	temp = "0x";

	arphead.mac_src = extract_mac_address(start, 44);

	// Per ora e' inutile.
	// arphead.mac_dst = extract_mac_address(start, 64);

	arphead.ip_src = extract_ipv4_address(start, 56);

	arphead.ip_dst = extract_ipv4_address(start, 76);

	return arphead;
}

header_ipv4 parseIPV4(std::string start)
{
	header_ipv4 ipv4;
	
	int i;
	std::string temp;
	temp.reserve(4);
	temp = "0x";

	for(i=47;i<=48;i++)	// Protocol Type
	{
		temp += start[i];
	}
	
	std::stringstream convert1 ( temp );

	convert1>> std::hex >> ipv4.protocol_type;
	
	ipv4.ip_src = extract_ipv4_address(start, 52);
	
	ipv4.ip_dst = extract_ipv4_address(start, 60);
	
	return ipv4;
	
}
