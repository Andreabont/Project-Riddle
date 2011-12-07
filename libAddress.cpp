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

#include <string>
#include <sstream>
#include <iomanip>
#include "libAddress.h"

void mac_address::set(std::string packet, int start)
{
	int i;
	int l = 0;
	std::string temp;
	temp.reserve(2);

	for(i=start;i<=start+11;i++)
	{
		temp += packet[i];
		if(i%2 != 0)
		{
			std::stringstream convert(temp);
			convert>>std::hex>>byte[l];
			l++;
			temp = "";
		}
	}
	
	return;
}

std::string mac_address::print()
{
  	std::string stamp;
	std::stringstream temp;
	int i;

	for(i=0;i<=5;i++)
	{
		temp<<std::setfill('0')<<std::setw(2)<<std::hex<<(int) byte[i];
		stamp += temp.str();
		temp.str("");
		if(i != 5) stamp += ':';
	}

	return stamp;
}

void ipv4_address::set(std::string packet, int start)
{
	int i;
	int l = 0;
	std::string temp;
	temp.reserve(2);

	for(i=start;i<=start+7;i++)
	{
		temp += packet[i];
		if(i%2 != 0)
		{
			std::stringstream convert(temp);
			convert>>std::hex>>byte[l];
			l++;
			temp = "";
		}
	}
	
	return;
}

std::string ipv4_address::print()
{
	std::string stamp;
	std::stringstream temp;
	int i;

	for(i=0;i<=3;i++)
	{
		temp<<std::dec<<byte[i];
		stamp += temp.str();
		temp.str("");
		if(i != 3) stamp += '.';;
	}

	return stamp;
}

void ipv6_address::set(std::string packet, int start)
{
  //TODO
}

std::string ipv6_address::print()
{
  //TODO
}
