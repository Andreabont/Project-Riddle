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

header_ethernet parseEthernet(std::string start)
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

header_arp parseArp(std::string start)
{
	header_arp arphead;
	
	int i;
	std::string temp;
	
	arphead.mac_dst.reserve(17);
	arphead.mac_src.reserve(17);
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
	
	for(i=44;i<=55;i++)	// Sender MAC
	{
		arphead.mac_src += start[i];
		if(i%2 != 0 && i != 55) arphead.mac_src += ':';
	}
	
	for(i=56;i<=63;i++)	// Sender IP
	{
		arphead.ip_src += start[i];
		if(i%2 != 0 && i != 63) arphead.ip_src += '.';
	}
	
	for(i=64;i<=75;i++)	// Target MAC
	{
		arphead.mac_dst += start[i];
		if(i%2 != 0 && i != 75) arphead.mac_dst += ':';
	}
	
	for(i=76;i<=83;i++)	// Target IP
	{
		arphead.ip_dst += start[i];
		if(i%2 != 0 && i != 83) arphead.ip_dst += '.';
	}
	
	return arphead;
}

std::string ether_type_decode(int start)
{	
	// Maggiore o uguale di 1536(0x0600) per Ethernet v2, minore per versione IEEE 802.3
	
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

void decDump(std::string line)
{
	header_ethernet etherhead;
	header_arp arphead;
	
	etherhead = parseEthernet(line);
	std::cout<<"---- Packet ("<<std::dec<<line.length()<<" byte)"<<std::endl;
	std::cout<<"EtherAddr | "<<etherhead.mac_src<<" --> "<<etherhead.mac_dst<<std::endl;
	std::cout<<"EtherType | 0x"<<std::hex<<etherhead.ether_type<<" ("<<ether_type_decode(etherhead.ether_type)<<")"<<std::endl;
	
	if(etherhead.ether_type == ETHER_TYPE_ARP)
	{
		arphead = parseArp(line);
		std::cout<<"ARP       | "<<arphead.mac_src<<" ("<<arphead.ip_src<<") --> "<<arphead.mac_dst<<" ("<<arphead.ip_dst<<")"<<std::endl;
	}
	
	std::cout<<std::endl;
	
	return;
}

void rawDump(std::string line)
{
	std::cout<<line<<std::endl;
	return;
}