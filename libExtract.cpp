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
#include <iomanip>
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

std::string print_mac_address(mac_address mac)
{
	std::string stamp;
	std::stringstream temp;
	int i;

	for(i=0;i<=5;i++)
	{
		temp<<std::setfill('0')<<std::setw(2)<<std::hex<<(int) mac.byte[i];
		stamp += temp.str();
		temp.str("");
		if(i != 5) stamp += ':';
	}

	return stamp;
}

std::string print_ipv4_address(ipv4_address ip)
{
	std::string stamp;
	std::stringstream temp;
	int i;

	for(i=0;i<=3;i++)
	{
		temp<<ip.byte[i];
		stamp += temp.str();
		temp.str("");
		if(i != 3) stamp += '.';;
	}

	return stamp;
}

mac_address extract_mac_address(std::string packet, int start)
{
	int i;
	int l = 0;
	std::string temp;
	temp.reserve(2);
	mac_address mac;

	for(i=start;i<=start+11;i++)
	{
		temp += packet[i];
		if(i%2 != 0)
		{
			std::stringstream convert(temp);
			convert>>std::hex>>mac.byte[l];
			l++;
			temp = "";
		}
	}

	return mac;
}

ipv4_address extract_ipv4_address(std::string packet, int start)
{
	int i;
	int l = 0;
	std::string temp;
	temp.reserve(2);
	ipv4_address ip;

	for(i=start;i<=start+7;i++)
	{
		temp += packet[i];
		if(i%2 != 0)
		{
			std::stringstream convert(temp);
			convert>>std::dec>>ip.byte[l];
			l++;
			temp = "";
		}
	}

	return ip;
}
