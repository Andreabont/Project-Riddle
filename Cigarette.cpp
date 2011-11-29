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
		std::cout<<"Ether | "<<print_mac_address(etherhead.mac_src);
		std::cout<<" --> "<<print_mac_address(etherhead.mac_dst)<<std::endl;
		std::cout<<"Ether | Type: 0x"<<std::hex<<etherhead.ether_type<<" ";
		std::cout<<"("<<ether_type_decode(etherhead.ether_type)<<")"<<std::endl;

		switch(etherhead.ether_type)
		{
			case ETHER_TYPE_ARP:
			header_arp arp;
			arp = parseArp(line);
			if(arp.opcode == 1)
			{
				// Request
				cout<<"ARP   | Who has "<<print_ipv4_address(arp.ip_dst)<<"? ";
				cout<<"Tell "<<print_mac_address(arp.mac_src)<<" ";
				cout<<"("<<print_ipv4_address(arp.ip_src)<<")"<<endl;
			}
			else
			{
				// Reply
			}
			break;
			case ETHER_TYPE_IPV4:
			break;
			case ETHER_TYPE_IPV6:
			break;
			default:
			break;
		}

		std::cout<<std::endl;

	}

	return EXIT_SUCCESS;
}
