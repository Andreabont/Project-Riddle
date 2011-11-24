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

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <boost/program_options.hpp>
#include "libCigarette.h"

using namespace std;
using namespace boost::program_options;

int main(int argc, char **argv) {
	options_description desc("Cigarette - Network Packet Parser");
	desc.add_options()
		("help", "prints this")
		("dump", "enable dump mode")
		("ipv4", "show only IPv4 Packets")
		("ipv6", "show only IPv6 Packets")
		("arp", "show only ARP Packets")
	;

	variables_map vm;
	store(parse_command_line(argc, argv, desc), vm);
	notify(vm);

	if(vm.count("help"))
	{
	    cout<<desc<<"\n";
	    return 1;
	}

	header_ethernet etherhead;
	
	void (*dumper)(std::string);
	if(vm.count("dump")) dumper=decDump; else dumper=rawDump;

	while(1)
	{
		string line;
		getline(cin,line);
		if(cin.eof()) break;
		etherhead = parseEthernet(line);
		
		int flag = 0;
		
		// TODO Da ottimizzare, magari sotto un unico parametro.
		if(vm.count("arp") || vm.count("ipv4") || vm.count("ipv6"))
		{
			if(vm.count("arp") && etherhead.ether_type == ETHER_TYPE_ARP) flag = 1;
			if(vm.count("ipv4") && etherhead.ether_type == ETHER_TYPE_IPV4) flag = 1;
			if(vm.count("ipv6") && etherhead.ether_type == ETHER_TYPE_IPV6) flag = 1;
		} else flag = 1;
		
		if(flag) dumper(line);
	}

	return EXIT_SUCCESS;
}
