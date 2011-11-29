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

	convert>> std::hex >> etherhead.ether_type;

	return etherhead;
}

header_arp parseArp(std::string start)
{
	header_arp arphead;

	int i;
	std::string temp;
	temp.reserve(6);
	temp = "0x";

	for(i=28;i<=31;i++)	// Hardware Type
	{
		temp += start[i];
	}

	std::stringstream convert ( temp );

	convert>> std::hex >> arphead.hardware_type;

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