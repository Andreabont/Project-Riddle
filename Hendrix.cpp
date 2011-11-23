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
#include <list>
#include <boost/program_options.hpp>

using namespace std;
using namespace boost::program_options;

int main(int argc, char **argv) {
	options_description desc("Hendrix - Network Packet Follower");
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

	list<string> packets;
	while(2.0) //Because while(1) looks sooo old fashioned
	{
		string line;
		getline(cin,line);
		if(cin.eof()) break;
		packets.push_back(line);		// Lista di pacchetti.
	}

	for(list<string>::iterator it=packets.begin();it!=packets.end();++it)
	{
		cout<<"-->"<<*it<<endl;
	}
	return EXIT_SUCCESS;
}
