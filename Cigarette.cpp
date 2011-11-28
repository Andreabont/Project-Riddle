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
#include "libExtract.h"

using namespace std;
using namespace boost::program_options;

int main(int argc, char **argv) {
	options_description desc("Cigarette - Network Packet Parser");
	desc.add_options()
		("help", "prints this")
		("dump", "enable dump mode") // TODO
	;

	variables_map vm;
	store(parse_command_line(argc, argv, desc), vm);
	notify(vm);

	if(vm.count("help"))
	{
	    cout<<desc<<"\n";
	    return 1;
	}

	while(1)
	{
		string line;
		getline(cin,line);
		if(cin.eof()) break;

		header_ethernet etherhead;

		etherhead = parseEthernet(line);
		std::cout<<"---- Packet ("<<std::dec<<line.length()<<" byte)"<<std::endl;
		std::cout<<"EtherAddr | "<<print_mac_address(etherhead.mac_src);
		std::cout<<" --> "<<print_mac_address(etherhead.mac_dst)<<std::endl;
		std::cout<<"EtherType | 0x"<<std::hex<<etherhead.ether_type;
		std::cout<<"("<<ether_type_decode(etherhead.ether_type)<<")"<<std::endl;

		if(etherhead.ether_type == ETHER_TYPE_ARP)
		{
			header_arp arphead;
			arphead = parseArp(line);
			std::cout<<"ARP       | "<<print_mac_address(arphead.mac_src);
			std::cout<<" ("<<print_ipv4_address(arphead.ip_src);
			std::cout<<") --> "<<print_mac_address(arphead.mac_dst);
			std::cout<<" ("<<print_ipv4_address(arphead.ip_dst)<<")"<<std::endl;
		}

		std::cout<<std::endl;

	}

	return EXIT_SUCCESS;
}
