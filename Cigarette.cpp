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
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "libCigarette.h"
#include "libAddress.h"
#include "libPacket.h"

using namespace std;
using namespace boost::program_options;

int main(int argc, char **argv) {
	options_description desc("Cigarette - Network Packet Parser");
	desc.add_options()
		("help", "prints this")
		("verbose", "enable verbose mode") // TODO
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
		string r_packet;
		getline(cin,r_packet);
		if(cin.eof()) break;

		std::vector< std::string > line;
		boost::algorithm::split(line, r_packet, boost::algorithm::is_any_of("!"));

		ethernet_header ethernet;
		
		
		ethernet.getMacAddress(line[2]);
		ethernet.getProtocolType(line[2]);
		
		std::cout<<"----- ["<<line[0]<<" "<<line[1]; 
		std::cout<<"] Packet ("<<std::dec<<line[2].length()<<" byte)"<<std::endl;
		std::cout<<"Ether | "<<ethernet.mac_src.print();
		std::cout<<" --> "<<ethernet.mac_dst.print()<<std::endl;
		std::cout<<"Ether | Type: 0x"<<std::hex<<ethernet.protocol_type<<" ";
		std::cout<<"("<<ether_type_decode(ethernet.protocol_type)<<")"<<std::endl;

		switch(ethernet.protocol_type)
		{
			case ETHER_TYPE_ARP:
			
			arp_header arp;
			arp.getIpAddress(line[2]);
			arp.getMacAddress(line[2]);
			arp.getOpcode(line[2]);
			
			if(arp.opcode == 1)
			{
				// Request
				cout<<"ARP   | Who has "<<arp.ip_dst.print()<<"? ";
				cout<<"Tell "<<arp.mac_src.print()<<" ";
				cout<<"("<<arp.ip_src.print()<<")"<<endl;
			}
			else
			{
				// Reply
				cout<<"ARP   | "<<arp.ip_src.print()<<" is at ";
				cout<<arp.mac_src.print()<<endl;
			}
			break;
			case ETHER_TYPE_IPV4:
			  
			ipv4_header ipv4;
			ipv4.getIpAddress(line[2]);
			ipv4.getProtocolType(line[2]);
			
			cout<<"IPV4  | "<<ipv4.ip_src.print()<<" --> "<<ipv4.ip_dst.print()<<endl;
			cout<<"IPV4  | Type: 0x"<<std::hex<<ipv4.protocol_type;
			cout<<" ("<<ipv4_type_decode(ipv4.protocol_type)<<")"<<endl;
			
				switch(ipv4.protocol_type)
				{
					case IPV4_TYPE_TCP:
						cout<<"TCP   | Flag: "<<endl;
					break;
					default:
					break;
				}
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
