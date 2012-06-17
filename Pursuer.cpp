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
 *  The project Riddle is free software: you can redistribute it and/or modify
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
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <boost/date_time.hpp>
#include <sys/time.h>
#include "./libraries/libCigarette.h"
#include "./commons/classMacAddress.h"
#include "./commons/classPacket.h"
#include "./libraries/libPursuer.h"

using namespace std;
using namespace boost;
using namespace boost::program_options;
using namespace libNetwork;

boost::mutex mymutex;
bool thread_alive;

/** Hello, my job is clean up and finalize the flows */
void dustman ( std::list<stream*> packet_stream ) {

    static boost::posix_time::seconds delay ( 1 );
    static int maxBufferLength = 512;		// byte
    static int maxFlowLength = 2*1024*1024;	// byte
    static unsigned int maxTime = 20;		// second

    while ( 1 ) {

        boost::mutex::scoped_lock mylock ( mymutex, boost::defer_lock ); // defer_lock makes it initially unlocked

        mylock.lock();

        cerr << "take lock" << endl;

        for ( list<stream*>::iterator element = packet_stream.begin(); element != packet_stream.end(); element++ ) {

            if ( ! ( *element )->firstFIN() && ( *element )->getFirstBufferLength() > maxBufferLength ) {
                ( *element )->flushFirstBuffer();
            }

            if ( ! ( *element )->secondFIN() && ( *element )->getSecondBufferLength() > maxBufferLength ) {
                ( *element )->flushSecondBuffer();
            }

            if ( ( ( *element )->firstFIN() && ( *element )->secondFIN() ) || ( *element )->getFlowLength() > maxFlowLength || time ( NULL ) > ( *element )->getTimeEpoch() + maxTime ) {

                ( *element )->flushFirstBuffer();
                ( *element )->flushSecondBuffer();
                writeout ( ( *element ), false );
                packet_stream.erase ( element );
            }

        }

        mylock.unlock();

        if ( !thread_alive ) {
            return;
        }

        boost::this_thread::sleep ( delay );
    }

}

int main ( int argc, char **argv ) {
    options_description desc ( "Pursuer - Network TCP Follower" );
    desc.add_options()
    ( "help", "prints this" )
    ( "tofile", "redirect payload to file (a file for each stream)" )
    ;

    variables_map vm;
    store ( parse_command_line ( argc, argv, desc ), vm );
    notify ( vm );

    if ( vm.count ( "help" ) ) {
        cout<<desc<<"\n";
        return EXIT_SUCCESS;
    }

    std::list<stream*> packet_stream;

    thread_alive == true;

    boost::thread workerThread ( dustman, packet_stream );

    workerThread.join();

    string r_packet;

    while ( 1 ) {
        try {

            getline ( cin,r_packet );
            if ( cin.eof() ) break;

            packet* pkg = packet::factory ( r_packet );

            if ( pkg->isIPv4() ) {
                IPv4packet *pkg_ipv4 = dynamic_cast<IPv4packet*> ( pkg );

                if ( pkg_ipv4->isTCP() ) {

                    TCPv4packet *pkg_tcpv4 = dynamic_cast<TCPv4packet*> ( pkg );

                    boost::mutex::scoped_lock mylock ( mymutex, boost::defer_lock ); // defer_lock makes it initially unlocked

                    mylock.lock();

                    if ( pkg_tcpv4->isSYN() && !pkg_tcpv4->isACK() ) {

                        stream *temp = new stream();
                        temp->factory ( pkg_tcpv4 );
                        packet_stream.push_back ( temp );
                    } else {

                        for ( list<stream*>::iterator it = packet_stream.begin(); it != packet_stream.end(); it++ ) {
                            // MA LOL !!!!!
                            if ( ( ( ( *it )->getFirstIpAddress() == pkg_tcpv4->getSenderIp() && ( *it )->getFirstPort() == pkg_tcpv4->getSenderPort() ) &&
                                    ( ( *it )->getSecondIpAddress() == pkg_tcpv4->getTargetIp() && ( *it )->getSecondPort() == pkg_tcpv4->getTargetPort() ) ) ||
                                    ( ( ( *it )->getFirstIpAddress() == pkg_tcpv4->getTargetIp() && ( *it )->getFirstPort() == pkg_tcpv4->getTargetPort() ) &&
                                      ( ( *it )->getSecondIpAddress() == pkg_tcpv4->getSenderIp() && ( *it )->getSecondPort() == pkg_tcpv4->getSenderPort() ) ) ) {

                                if ( pkg_tcpv4->isSYN() ) {
                                    ( *it )->factory ( pkg_tcpv4 );
                                } else {
                                    ( *it )->addPacket ( pkg_tcpv4 );
                                }
                                break;
                            }

                        }

                    }

                    mylock.unlock();

                }

            }

        } catch ( packet::Overflow ) {
            thread_alive == false;
            std::cerr<<"Overflow! :-P"<<std::endl;
            return EXIT_FAILURE;
        }
    }

    // Esporto fussi non terminati prima dell'uscita.
    // Non usare il for, non va d'accordo con gli erase.

    thread_alive == false;

    boost::mutex::scoped_lock lastlock ( mymutex, boost::defer_lock ); // defer_lock makes it initially unlocked

    lastlock.lock();

    while ( !packet_stream.empty() ) {

        list<stream*>::iterator it3 = packet_stream.begin();
        ( *it3 )->flushFirstBuffer();
        ( *it3 )->flushSecondBuffer();
        writeout ( ( *it3 ), vm.count ( "tofile" ) );
        packet_stream.erase ( it3 );

    }

    return EXIT_SUCCESS;
}


