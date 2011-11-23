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

	while(1)
	{
		string line;
		getline(cin,line);
		if(cin.eof()) break;
		etherhead = parseEthernet(line,line.length());
		cout<<"---- Packet ("<<dec<<line.length()<<" byte)"<<endl;
		cout<<"EtherAddr | "<<etherhead.mac_src<<" --> "<<etherhead.mac_dst<<endl;
		cout<<"EtherType | 0x"<<hex<<etherhead.ether_type<<" ("<<ether_type_decode(etherhead.ether_type)<<")"<<endl;
		cout<<endl;
	}

	return EXIT_SUCCESS;
}
