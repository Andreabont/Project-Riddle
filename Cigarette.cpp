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

using namespace std;
using namespace boost;
using namespace boost::program_options;

int main(int argc, char **argv) {
    options_description desc("Cigarette - Network Packet Parser");
    desc.add_options()
    ("help", "prints this")
    ("tcp", "expand TCP info")
    ("icmp", "expand ICMP info")
    ;

    variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if (vm.count("help"))
    {
        cout<<desc<<"\n";
        return 1;
    }

    while (1)
    {
        try
        {
            string r_packet;
            getline(cin,r_packet);
            if (cin.eof()) break;

            std::vector< std::string > line;
            boost::algorithm::split(line, r_packet, boost::algorithm::is_any_of("!"));

            packet* pkg = packet::factory(lexical_cast<int>(line[0]), lexical_cast<int>(line[1]), line[2]);

            cout << "[" << std::dec << pkg->getEpoch() << " " << setfill('0') << std::setw(6) << pkg->getMillis() << "] Size: " << pkg->getLength() << " byte" << endl;
            cout << "                    From " << pkg->getSenderMac().to_string() << " to "<< pkg->getTargetMac().to_string() << endl;
            cout << "                    EtherType: 0x" << std::hex << pkg->getEtherType() << " ("<< ether_type_decode(pkg->getEtherType()) << ")" << endl;
            cout << endl;

            if (pkg->isArp())
            {

                ARPpacket *pkg_arp = dynamic_cast<ARPpacket*>(pkg);

                if (pkg_arp->getOpCode() == 1)
                {
                    cout << "                    Who has " << pkg_arp->getTargetIp().to_string() << " ? Tell "<< pkg_arp->getSenderIp().to_string() << endl;
                    cout << endl;

                } else {

                    cout << "                    " << pkg_arp->getSenderIp().to_string() << " is at "<< pkg->getSenderMac().to_string() << endl;
                    cout << endl;

                }

            } else if (pkg->isIPv4())
            {

                IPv4packet *pkg_ipv4 = dynamic_cast<IPv4packet*>(pkg);

                cout << "                    From " << pkg_ipv4->getSenderIp().to_string() << " to "<< pkg_ipv4->getTargetIp().to_string() << endl;
                cout << "                    ProtocolType: 0x" << pkg_ipv4->getProtocolType() << " ("<< ipv4_type_decode(pkg_ipv4->getProtocolType()) << ")" << endl;
                cout << endl;

                if (pkg_ipv4->isTCP())
                {

                    TCPv4packet* pkg_tcpv4 = dynamic_cast<TCPv4packet*>(pkg);

                    cout << "                    From port " << std::dec << pkg_tcpv4->getSenderPort() << " to port " << pkg_tcpv4->getTargetPort() << endl;

                    if (vm.count("tcp"))
                    {
                        cout << "                    + Sequence Number        " << pkg_tcpv4->getSequenceNumber() << endl;
                        cout << "                    + Acknowledgment Number  " << pkg_tcpv4->getAcknowledgmentNumber() << endl;
                        cout << "                    + Window Size            " << pkg_tcpv4->getWindowSize() << " byte" <<endl;
                        cout << "                    + Flags                  ";
                        if(pkg_tcpv4->isSYN()) cout << "SYN ";
                        if(pkg_tcpv4->isFIN()) cout << "FIN ";
                        if(pkg_tcpv4->isRST()) cout << "RST ";
                        if(pkg_tcpv4->isACK()) cout << "ACK ";
                        if(pkg_tcpv4->isPSH()) cout << "PSH ";
                        if(pkg_tcpv4->isURG()) cout << "URG ";
                        if(pkg_tcpv4->isECE()) cout << "ECE ";
                        if(pkg_tcpv4->isCWR()) cout << "CWR ";
                        cout << endl;
                    }

                    cout << endl;

                } else if (pkg_ipv4->isUDP())
                {

                    UDPv4packet* pkg_udpv4 = dynamic_cast<UDPv4packet*>(pkg);

                    cout << "                    From port " << std::dec << pkg_udpv4->getSenderPort() << " to port " << pkg_udpv4->getTargetPort() << endl;
                    cout << endl;

                } else if (pkg_ipv4->isICMP())
                {

                    ICMPv4packet* pkg_icmpv4 = dynamic_cast<ICMPv4packet*>(pkg);

                    cout << "                    Message Type: " << pkg_icmpv4->getMessageType() << " (" << icmpv4_type_decode(pkg_icmpv4->getMessageType()) << ")" << endl;
                    
		    if (vm.count("icmp"))
		    {
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
        }
        catch (packet::Overflow)
        {
            std::cerr<<"Overflow! :-P"<<std::endl;
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
