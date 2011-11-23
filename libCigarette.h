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

struct header_ethernet
{
	std::string mac_dst;
	std::string mac_src;
	std::string next_protocol;
};

header_ethernet parseEthernet(std::string start, int len);

#endif //LIBCIGARETTE_H
