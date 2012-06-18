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
#include <cstdio>
#include <cstdlib>
#include <string>
#include <iomanip>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include "./libraries/libCigarette.h"
#include "./commons/classMacAddress.h"
#include "./commons/classPacket.h"
#include "./commons/libDump.h"

using namespace std;
using namespace boost;
using namespace boost::program_options;
using namespace libNetwork;

int main ( int argc, char **argv ) {
    options_description desc ( "Cigarette - Network Packet Parser" );
    desc.add_options()
    ( "help", "prints this" )
    ( "ipv4", "expand IPv4 info" )
    ( "tcp", "expand TCP info" )
    ( "icmp", "expand ICMP info" )
    ( "payload", "print payload dump" )
    ;

    variables_map vm;
    store ( parse_command_line ( argc, argv, desc ), vm );
    notify ( vm );

    if ( vm.count ( "help" ) ) {
        cout<<desc<<"\n";
        return 1;
    }

    while ( 1 ) {
        try {
            string r_packet;
            getline ( cin,r_packet );
            if ( cin.eof() ) break;

            packet* pkg = packet::factory ( r_packet );


            cout << "[" << std::dec << pkg->getEpoch() << " " << setfill ( '0' ) << std::setw ( 6 ) << pkg->getMillis() << "] Size: " << pkg->getPacketLength() << " byte" << endl;
            cout << "                    From " << pkg->getSenderMac().to_string() << " to "<< pkg->getTargetMac().to_string() << endl;
            cout << "                    EtherType: 0x" << std::hex << pkg->getEtherType() << " ("<< ether_type_decode ( pkg->getEtherType() ) << ")" << endl;
            cout << endl;

            if ( pkg->isArp() ) {

                ARPpacket *pkg_arp = dynamic_cast<ARPpacket*> ( pkg );

                if ( pkg_arp->getOpCode() == 1 ) {
                    cout << "                    Who has " << pkg_arp->getTargetIp().to_string() << " ? Tell "<< pkg_arp->getSenderIp().to_string() << endl;
                    cout << endl;

                } else {

                    cout << "                    " << pkg_arp->getSenderIp().to_string() << " is at "<< pkg->getSenderMac().to_string() << endl;
                    cout << endl;

                }

            } else if ( pkg->isIPv4() ) {

                IPv4packet *pkg_ipv4 = dynamic_cast<IPv4packet*> ( pkg );

                cout << "                    From " << pkg_ipv4->getSenderIp().to_string() << " to "<< pkg_ipv4->getTargetIp().to_string() << endl;
                cout << "                    ProtocolType: 0x" << pkg_ipv4->getProtocolType() << " ("<< ipv4_type_decode ( pkg_ipv4->getProtocolType() ) << ")" << endl;

                if ( vm.count ( "ipv4" ) ) {
                    cout << "                    + Time To Live           " << std::dec << pkg_ipv4->getTTL() << endl;
                    cout << "                    + Identification         0x" << std::hex << pkg_ipv4->getIdentity() << endl;;
                    cout << "                    + Checksum               0x" << std::hex << pkg_ipv4->getIPChecksum();
                    if ( pkg_ipv4->verifyIPChecksum() ) {
                        cout << " (Correct) ";
                    } else {
                        cout << " (Invalid) ";
                    }
                    cout << endl;
                }

                cout << endl;

                if ( pkg_ipv4->isTCP() ) {

                    TCPv4packet* pkg_tcpv4 = dynamic_cast<TCPv4packet*> ( pkg );

                    cout << "                    From port " << std::dec << pkg_tcpv4->getSenderPort() << " to port " << pkg_tcpv4->getTargetPort() << endl;

                    if ( vm.count ( "tcp" ) ) {
                        cout << "                    + Sequence Number        " << pkg_tcpv4->getSequenceNumber() << endl;
			cout << "                    + Next Sequence Number   " << pkg_tcpv4->getSequenceNumber() + pkg_tcpv4->getPayloadLength() << endl;
                        cout << "                    + Acknowledgment Number  " << pkg_tcpv4->getAcknowledgmentNumber() << endl;
                        cout << "                    + Header Length          " << pkg_tcpv4->getHeaderLength() << " byte" << endl;
			cout << "                    + Payload Length         " << pkg_tcpv4->getPayloadLength() << " byte" << endl;
			cout << "                    + Window Size            " << pkg_tcpv4->getWindowSize() << " byte" << endl;
                        cout << "                    + Flags                  ";
                        if ( pkg_tcpv4->isSYN() ) cout << "SYN ";
                        if ( pkg_tcpv4->isFIN() ) cout << "FIN ";
                        if ( pkg_tcpv4->isRST() ) cout << "RST ";
                        if ( pkg_tcpv4->isACK() ) cout << "ACK ";
                        if ( pkg_tcpv4->isPSH() ) cout << "PSH ";
                        if ( pkg_tcpv4->isURG() ) cout << "URG ";
                        if ( pkg_tcpv4->isECE() ) cout << "ECE ";
                        if ( pkg_tcpv4->isCWR() ) cout << "CWR ";
                        cout << endl;
                        cout << "                    + Checksum               0x" << std::hex << pkg_tcpv4->getTCPChecksum() << endl;
                        cout << "                    + Urgent Pointer         0x" << std::hex << pkg_tcpv4->getUrgentPointer() << endl;
                        std::map<int, std::string> options = pkg_tcpv4->getOptionMap();

                        if ( pkg_tcpv4->isOption() ) {
                            std::map<int, std::string>::const_iterator itr;

                            for ( itr = options.begin(); itr != options.end(); ++itr ) {
                                cout << "                    + Option                 " << ( *itr ).first << " -> " << ( *itr ).second << endl;
                            }
                        }
                    }

                    if ( vm.count ( "payload" ) ) {
                        cout << "                    + Payload:" << endl;
                        cout << libDump::classicDump ( pkg_tcpv4->getPayLoad() ) << endl;
                    }



                    cout << endl;

                } else if ( pkg_ipv4->isUDP() ) {

                    UDPv4packet* pkg_udpv4 = dynamic_cast<UDPv4packet*> ( pkg );

                    cout << "                    From port " << std::dec << pkg_udpv4->getSenderPort() << " to port " << pkg_udpv4->getTargetPort() << endl;
                    cout << endl;

                } else if ( pkg_ipv4->isICMP() ) {

                    ICMPv4packet* pkg_icmpv4 = dynamic_cast<ICMPv4packet*> ( pkg );

                    cout << "                    Message Type: " << pkg_icmpv4->getMessageType() << " (" << icmpv4_type_decode ( pkg_icmpv4->getMessageType() ) << ")" << endl;

                    if ( vm.count ( "icmp" ) ) {
                        cout << "                    Message Code: " << pkg_icmpv4->getMessageCode() << endl;
                    }

                    cout << endl;

                } else {
                    cout << "                    Unknown Packet" << endl;
                    cout << endl;
                }

            } else {
                cout << "                    Unknown Packet" << endl;
                cout << endl;
            }

            delete pkg;
        } catch ( packet::Overflow ) {
            std::cerr<<"Overflow! :-P"<<std::endl;
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
