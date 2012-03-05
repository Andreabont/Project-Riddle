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

                if (((ARPpacket*)pkg)->getOpCode() == 1)
                {
                    cout << "                    Who has " << ((ARPpacket*)pkg)->getTargetIp().to_string() << " ? Tell "<< ((ARPpacket*)pkg)->getSenderIp().to_string() << endl;
                    cout << endl;

                } else {

                    cout << "                    " << ((ARPpacket*)pkg)->getSenderIp().to_string() << " is at "<< pkg->getSenderMac().to_string() << endl;
                    cout << endl;

                }

            } else if (pkg->isIPv4())
            {

                cout << "                    From " << ((IPv4packet*)pkg)->getSenderIp().to_string() << " to "<< ((IPv4packet*)pkg)->getTargetIp().to_string() << endl;
                cout << "                    ProtocolType: 0x" << ((IPv4packet*)pkg)->getProtocolType() << " ("<< ipv4_type_decode(((IPv4packet*)pkg)->getProtocolType()) << ")" << endl;
                cout << endl;

                if (((IPv4packet*)pkg)->isTCP())
                {

                    cout << "                    From port " << std::dec << ((TCPv4packet*)pkg)->getSenderPort() << " to port " << ((TCPv4packet*)pkg)->getTargetPort() << endl;
		    
		    if (vm.count("tcp"))
		    {
			cout << "                    + Sequence Number        " << ((TCPv4packet*)pkg)->getSequenceNumber() << endl;
			cout << "                    + Acknowledgment Number  " << ((TCPv4packet*)pkg)->getAcknowledgmentNumber() << endl;
			cout << "                    + Window Size            " << ((TCPv4packet*)pkg)->getWindowSize() << " byte" <<endl;
			cout << "                    + Flags                  ";
			if(((TCPv4packet*)pkg)->isSYN()) cout << "SYN ";
			if(((TCPv4packet*)pkg)->isFIN()) cout << "FIN ";
			if(((TCPv4packet*)pkg)->isRST()) cout << "RST ";
			if(((TCPv4packet*)pkg)->isACK()) cout << "ACK ";
			if(((TCPv4packet*)pkg)->isPSH()) cout << "PSH ";
			if(((TCPv4packet*)pkg)->isURG()) cout << "URG ";
			if(((TCPv4packet*)pkg)->isECE()) cout << "ECE ";
			if(((TCPv4packet*)pkg)->isCWR()) cout << "CWR ";
			cout << endl;
		    }
		    
		    cout << endl;

                } else if (((IPv4packet*)pkg)->isUDP())
                {

                    cout << "                    From port " << std::dec << ((UDPv4packet*)pkg)->getSenderPort() << " to port " << ((UDPv4packet*)pkg)->getTargetPort() << endl;
		    cout << endl;
		  
                } else if (((IPv4packet*)pkg)->isICMP())
                {

                } else {

                }

            } else {

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
