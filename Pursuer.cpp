/**
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 * 
 * Name        :  Project Riddle
 * Author      :  Andrea Bontempi
 * Version     :  0.1 aplha
 * Description :  Modular Network Sniffer
 * 
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 * 
 * This file is part of the project Riddle.
 *
 *  Foobar is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The project Riddle is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this project.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 */

#include <iostream>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <iomanip>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include "./libraries/libCigarette.h"
#include "./commons/libAddress.h"
#include "./commons/libPacket.h"
#include "./libraries/libPursuer.h"

using namespace std;
using namespace boost;
using namespace boost::program_options;
using namespace libNetwork;

int main(int argc, char **argv) {
    options_description desc("Pursuer - Network TCP Follower");
    desc.add_options()
    ("help", "prints this")
    ("output",value<string>(), "redirect payload to file (a file for each stream)")
    ;

    variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if (vm.count("help"))
    {
        cout<<desc<<"\n";
        return 1;
    }

    std::list<stream*> packet_stream;

    string r_packet;

    while (1)
    {
        try
        {

            getline(cin,r_packet);
            if (cin.eof()) break;

            packet* pkg = packet::factory(r_packet);

            if(pkg->isIPv4())
            {
                IPv4packet *pkg_ipv4 = dynamic_cast<IPv4packet*>(pkg);

                if(pkg_ipv4->isTCP())
                {

                    TCPv4packet *pkg_tcpv4 = dynamic_cast<TCPv4packet*>(pkg);


                    if(pkg_tcpv4->isSYN() && !pkg_tcpv4->isACK())
                    {

                        stream *temp = new stream();
                        temp->factory(pkg_tcpv4);
                        packet_stream.push_back(temp);
                    }
                    else
                    {

                        for (list<stream*>::iterator it = packet_stream.begin(); it != packet_stream.end(); it++)
                        {
                            // MA LOL !!!!!
                            if( ( ( (*it)->getFirstIpAddress() == pkg_tcpv4->getSenderIp() && (*it)->getFirstPort() == pkg_tcpv4->getSenderPort()) &&
                                    ( (*it)->getSecondIpAddress() == pkg_tcpv4->getTargetIp() && (*it)->getSecondPort() == pkg_tcpv4->getTargetPort())) ||
                                    ( ( (*it)->getFirstIpAddress() == pkg_tcpv4->getTargetIp() && (*it)->getFirstPort() == pkg_tcpv4->getTargetPort()) &&
                                      ( (*it)->getSecondIpAddress() == pkg_tcpv4->getSenderIp() && (*it)->getSecondPort() == pkg_tcpv4->getSenderPort())))
                            {

                                if(pkg_tcpv4->isSYN())
                                {
                                    (*it)->factory(pkg_tcpv4);
                                }
                                else if(pkg_tcpv4->isRST() || pkg_tcpv4->isFIN())
                                {
                                    (*it)->flushFirstBuffer();
                                    (*it)->flushSecondBuffer();
				    
                                    if (vm.count("output"))
                                    {
					std::cout << (*it)->exportRawFlow() << std::endl;
                                    }
                                    else
                                    {
                                        std::cout << (*it)->exportFlow() << std::endl;
                                    }
                                    
                                    packet_stream.remove(*it);
                                    break;
                                }
                                else
                                {
                                    (*it)->addPacket(pkg_tcpv4);
                                }
                                break;
                            }

                        }

                    }

                }

            }
            
            
            // Pulizia stream non terminati.
            
            for (list<stream*>::iterator it2 = packet_stream.begin(); it2 != packet_stream.end(); it2++)
	    {
	      
	      if((*it2)->getTimeEpoch() > pkg->getEpoch() + (10*60) || (*it2)->getFlowLength() > (10*1024*1024))
	      {
		
		//packet_stream.remove(*it2); FIXME
		
	      } else if( (*it2)->getBufferLength() > 1024 )
	      {
		
		(*it2)->flushFirstBuffer();
		(*it2)->flushSecondBuffer();
		
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

