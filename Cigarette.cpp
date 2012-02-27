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
#include <boost/asio.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "libCigarette.h"
#include "libAddress.h"
#include "libPacket.h"

using namespace std;
using namespace boost;
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
	  try
	  {
		string r_packet;
		getline(cin,r_packet);
		if(cin.eof()) break;

		std::vector< std::string > line;
		boost::algorithm::split(line, r_packet, boost::algorithm::is_any_of("!"));

		packet::factory(lexical_cast<int>(line[0]), lexical_cast<int>(line[1]), line[2]);
		
		cout<<"Pacchetto " << lexical_cast<int>(line[0]) <<endl;
	  }
	  catch(packet::Overflow)
	  {
	    std::cerr<<"Overflow! :-P"<<std::endl;
	    return EXIT_FAILURE;
	  }
	  catch(packet::HeaderFault)
	  {
	    std::cerr<<"HeaderFault! :-P"<<std::endl;
	    return EXIT_FAILURE;
	  }
	}
	return EXIT_SUCCESS;
}
