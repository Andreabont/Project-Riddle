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
#include <iomanip>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "libCigarette.h"
#include "libAddress.h"
#include "libPacket.h"
#include "libPursuer.h"

using namespace std;
using namespace boost;
using namespace boost::program_options;

int main(int argc, char **argv) {
    options_description desc("Pursuer - Network TCP Follower");
    desc.add_options()
    ("help", "prints this")
    ;

    variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if (vm.count("help"))
    {
        cout<<desc<<"\n";
        return 1;
    }

    string r_packet;
    getline(cin,r_packet);
    if (cin.eof()) return EXIT_SUCCESS;

    std::list<stream*> packet_flow;

    while (1)
    {
        try
        {

            getline(cin,r_packet);
            if (cin.eof()) break;

            std::vector< std::string > line;
            boost::algorithm::split(line, r_packet, boost::algorithm::is_any_of("!"));

            packet* pkg = packet::factory(lexical_cast<int>(line[0]), lexical_cast<int>(line[1]), line[2]);

            if(pkg->isIPv4())
            {
                IPv4packet *pkg_ipv4 = dynamic_cast<IPv4packet*>(pkg);

                if(pkg_ipv4->isTCP())
                {

                    TCPv4packet *pkg_tcpv4 = dynamic_cast<TCPv4packet*>(pkg);

                    list<stream*>::iterator p = packet_flow.begin();
                    while(p != packet_flow.end()) {
                        cout << *p << " ";
                        p++;
                    }

                }
            }

        }
        catch (packet::Overflow)
        {
            std::cerr<<"Overflow! :-P"<<std::endl;
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
