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

#include <cstdio>
#include <stdint.h>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <ios>
#include <map>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "classMacAddress.h"
#include "classPacket.h"

/* PACKET */

libNetwork::packet* libNetwork::packet::factory ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {

    uint16_t protocol_type;

    std::string temp;
    temp.reserve ( 4 );

    for ( int i = 24; i <= 27; i++ ) {
        temp += rawData_i[i];
    }
    std::stringstream convert ( temp );
    convert>>std::hex>>protocol_type;

    packet *p;
    if ( protocol_type == ETHER_TYPE_ARP ) {

        p = new ARPpacket ( timeEpoch_i, timeMillis_i, rawData_i );

    } else if ( protocol_type == ETHER_TYPE_IPV4 ) {

        p = IPv4packet::factory ( timeEpoch_i, timeMillis_i, rawData_i );

    } else {

        p = new UnknownPacket ( timeEpoch_i, timeMillis_i, rawData_i );

    }

    return p;
}

libNetwork::packet* libNetwork::packet::factory ( std::string packetLine ) {
    std::vector< std::string > section;
    boost::algorithm::split ( section, packetLine, boost::algorithm::is_any_of ( "!" ) );

    packet* pkg = packet::factory ( boost::lexical_cast<int> ( section[0] ), boost::lexical_cast<int> ( section[1] ), section[2] );

    return pkg;
}

uint32_t libNetwork::packet::getPacketLength() {
    return pkgLength;
}

uint64_t libNetwork::packet::getEpoch() {
    return timeEpoch;
}

uint32_t libNetwork::packet::getMillis() {
    return timeMillis;
}

std::string libNetwork::packet::getHexString ( int string_cursor, int read_byte ) {
    std::string temp;
    temp.reserve ( read_byte * 2 );

    if ( string_cursor + read_byte > this->getPacketLength() ) throw Overflow();

    for ( int i = string_cursor * 2; i < ( string_cursor * 2 ) + ( read_byte * 2 ); i++ ) {
        temp += rawData[i];
    }

    return temp;
}

std::string libNetwork::packet::getDecimalIP ( int string_cursor ) {
    std::string temp;
    std::string stamp;
    temp.reserve ( 2 );

    for ( int i=0; i <= 7; i++ ) {
        temp += rawData[ ( string_cursor*2 ) +i];
        if ( i%2 != 0 ) {
            std::stringstream convert ( temp );
            int a;
            convert>>std::hex>>a;
            stamp += boost::lexical_cast<std::string> ( a );
            if ( i != 7 ) stamp += ".";
            temp = "";
        }
    }
    return stamp;
}

libNetwork::mac_address libNetwork::packet::getMacAddress ( int string_cursor ) {
    mac_address mac_temp ( this->getHexString ( string_cursor, 6 ) );
    return mac_temp;
}

bool libNetwork::packet::isArp() {
    return ( this->getEtherType() == ETHER_TYPE_ARP );
}

bool libNetwork::packet::isIPv4() {
    return ( this->getEtherType() == ETHER_TYPE_IPV4 );
}

bool libNetwork::packet::isIPv6() {
    return ( this->getEtherType() == ETHER_TYPE_IPV6 );
}

libNetwork::mac_address libNetwork::packet::getSenderMac() {
    return this->getMacAddress ( 6 );
}

libNetwork::mac_address libNetwork::packet::getTargetMac() {
    return this->getMacAddress ( 0 );
}

uint16_t libNetwork::packet::getEtherType() {
    uint16_t protocol_type;

    std::stringstream convert ( this->getHexString ( 12, 2 ) );
    convert>>std::hex>>protocol_type;

    return protocol_type;
}


/* ARP */

libNetwork::ARPpacket::ARPpacket ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {

    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

uint16_t libNetwork::ARPpacket::getOpCode() {
    uint16_t opcode;

    std::stringstream convert ( this->getHexString ( ARP_OFFSET+6, 2 ) );
    convert>>std::hex>>opcode;

    return opcode;
}


boost::asio::ip::address libNetwork::ARPpacket::getSenderIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( ARP_OFFSET+14 ) );
    return newaddr;
}

boost::asio::ip::address libNetwork::ARPpacket::getTargetIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( ARP_OFFSET+24 ) );
    return newaddr;
}

/* IPV4 */

libNetwork::packet* libNetwork::IPv4packet::factory ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    uint16_t protocol_type;

    std::string temp;
    temp.reserve ( 2 );

    for ( int i = 46; i <= 47; i++ ) {
        temp += rawData_i[i];
    }
    std::stringstream convert ( temp );
    convert>>std::hex>>protocol_type;

    packet *p;
    if ( protocol_type == IPV4_TYPE_TCP ) {

        p = new TCPv4packet ( timeEpoch_i, timeMillis_i, rawData_i );

    } else if ( protocol_type == IPV4_TYPE_UDP ) {

        p = new UDPv4packet ( timeEpoch_i, timeMillis_i, rawData_i );

    } else if ( protocol_type == IPV4_TYPE_ICMP ) {

        p = new ICMPv4packet ( timeEpoch_i, timeMillis_i, rawData_i );

    } else {

        p = new UnknownPacket ( timeEpoch_i, timeMillis_i, rawData_i );

    }

    return p;
}

boost::asio::ip::address libNetwork::IPv4packet::getSenderIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( IPv4_OFFSET+12 ) );
    return newaddr;
}

boost::asio::ip::address libNetwork::IPv4packet::getTargetIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( IPv4_OFFSET+16 ) );
    return newaddr;
}

uint16_t libNetwork::IPv4packet::getIdentity() {
    uint16_t id;

    std::stringstream convert ( this->getHexString ( IPv4_OFFSET+4, 2 ) );
    convert>>std::hex>>id;

    return id;
}

uint16_t libNetwork::IPv4packet::getTTL() {
    uint16_t ttl;

    std::stringstream convert ( this->getHexString ( IPv4_OFFSET+8, 1 ) );
    convert>>std::hex>>ttl;

    return ttl;
}

uint16_t libNetwork::IPv4packet::getProtocolType() {
    uint16_t protocol_type;

    std::stringstream convert ( this->getHexString ( IPv4_OFFSET+9, 1 ) );
    convert>>std::hex>>protocol_type;

    return protocol_type;
}

uint16_t libNetwork::IPv4packet::getIPChecksum() {
    uint16_t cs;
    std::stringstream convert ( this->getHexString ( IPv4_OFFSET+10, 2 ) );
    convert>>std::hex>>cs;
    return cs;
}

bool libNetwork::IPv4packet::verifyIPChecksum() {

    int sum = 0;

    for ( int i = 0; i < 20; i += 2 ) {

        short unsigned int temp;
        std::stringstream convert ( this->getHexString ( IPv4_OFFSET+i,2 ) );
        convert >> std::hex >> temp;
        sum += temp;

    }

    return ( ( sum & 0xFFFF ) + ( sum >>= 16 ) == 0xFFFF );
}

int libNetwork::IPv4packet::getFlagsIP() {
    int flag;
    std::stringstream convert ( this->getHexString ( IPv4_OFFSET+6, 1 ) );
    convert>>std::hex>>flag;
    return flag;
}

bool libNetwork::IPv4packet::isDF() {
    return ( this->getFlagsIP() & 64 );
}

bool libNetwork::IPv4packet::isMF() {
    return ( this->getFlagsIP() & 32 );
}

bool libNetwork::IPv4packet::isTCP() {
    return ( this->getProtocolType() == IPV4_TYPE_TCP );
}

bool libNetwork::IPv4packet::isUDP() {
    return ( this->getProtocolType() == IPV4_TYPE_UDP );
}

bool libNetwork::IPv4packet::isICMP() {
    return ( this->getProtocolType() == IPV4_TYPE_ICMP );
}

/* ICMP */

libNetwork::ICMPv4packet::ICMPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

uint16_t libNetwork::ICMPv4packet::getMessageType() {
    uint16_t  message_type;

    std::stringstream convert ( this->getHexString ( ICMPV4_OFFSET, 1 ) );
    convert>>std::hex>>message_type;

    return message_type;
}

uint16_t libNetwork::ICMPv4packet::getMessageCode() {
    uint16_t  message_code;

    std::stringstream convert ( this->getHexString ( ICMPV4_OFFSET+1, 1 ) );
    convert>>std::hex>>message_code;

    return message_code;
}

/* TCP */

libNetwork::TCPv4packet::TCPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    public_flag = false;
    return;
}

uint16_t libNetwork::TCPv4packet::getSenderPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET, 2 ) );
    convert>>std::hex>>port;
    return port;
}

uint16_t libNetwork::TCPv4packet::getTargetPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+2, 2 ) );
    convert>>std::hex>>port;
    return port;
}

uint32_t libNetwork::TCPv4packet::getSequenceNumber() {
    uint32_t sn;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+4, 4 ) );
    convert>>std::hex>>sn;
    return sn;
}

uint32_t libNetwork::TCPv4packet::getAcknowledgmentNumber() {
    uint32_t an;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+8, 4 ) );
    convert>>std::hex>>an;
    return an;
}

uint32_t libNetwork::TCPv4packet::getExpectedAcknowledgmentNumber() {
    return this->getSequenceNumber() + this->getPayloadLength();
}

unsigned int libNetwork::TCPv4packet::getHeaderLength() {
    /*
     * Sono utilizzati solo i primi 8 bit del byte, necessita traslazione.
     * Indica i gruppi da 32 bit contenuti, necessita conversione.
     */
    unsigned int hl;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+12, 1 ) );
    convert>>std::hex>>hl;
    hl >>= 4;
    hl = ( hl * 32 ) / 8;
    return hl;
}

unsigned int libNetwork::TCPv4packet::getPayloadLength() {
    return ( this->getPayLoad().length() ) /2;
}

int libNetwork::TCPv4packet::getFlagsTCP() {
    int flag;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+13, 1 ) );
    convert>>std::hex>>flag;
    return flag;
}

unsigned int libNetwork::TCPv4packet::getWindowSize() {
    unsigned int ws;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+14, 2 ) );
    convert>>std::hex>>ws;
    return ws;
}

unsigned int libNetwork::TCPv4packet::getTCPChecksum() {
    unsigned int cs;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+16, 2 ) );
    convert>>std::hex>>cs;
    return cs;
}

unsigned int libNetwork::TCPv4packet::getUrgentPointer() {
    unsigned int up;
    std::stringstream convert ( this->getHexString ( TCP_OFFSET+18, 2 ) );
    convert>>std::hex>>up;
    return up;
}

std::string libNetwork::TCPv4packet::getOptionRaw() {
    return this->getHexString ( TCP_OFFSET + TCP_STANDARD, this->getHeaderLength() - TCP_STANDARD );
}

std::map< int, std::string > libNetwork::TCPv4packet::getOptionMap() {
    std::map<int, std::string> tempMap;
    if ( this->isOption() && !this->isSYN() ) { // FIXME - SYN usa altro protocollo???
        for ( int i=0; i < ( this->getHeaderLength() - TCP_STANDARD ); i++ ) {
            int read;
            std::stringstream convert ( this->getHexString ( TCP_OFFSET+TCP_STANDARD+i, 1 ) );
            convert >> std::hex >> read;

            if ( read != 1 ) {
                std::stringstream convert2 ( this->getHexString ( TCP_OFFSET+TCP_STANDARD+i+1, 1 ) );
                int optionLength;
                convert2 >> std::hex >> optionLength;
                tempMap[read] = this->getHexString ( TCP_OFFSET+TCP_STANDARD+i+2, optionLength-2 );
                i += optionLength;
            }
        }
    }
    return tempMap;
}

std::string libNetwork::TCPv4packet::getPayLoad() {
    int start = TCP_OFFSET + this->getHeaderLength();
    return this->getHexString ( start, this->getPacketLength() - start );
}

bool libNetwork::TCPv4packet::isCWR() {
    return ( this->getFlagsTCP() & 128 );
}

bool libNetwork::TCPv4packet::isECE() {
    return ( this->getFlagsTCP() & 64 );
}

bool libNetwork::TCPv4packet::isURG() {
    return ( this->getFlagsTCP() & 32 );
}

bool libNetwork::TCPv4packet::isACK() {
    return ( this->getFlagsTCP() & 16 );
}

bool libNetwork::TCPv4packet::isPSH() {
    return ( this->getFlagsTCP() & 8 );
}

bool libNetwork::TCPv4packet::isRST() {
    return ( this->getFlagsTCP() & 4 );
}

bool libNetwork::TCPv4packet::isSYN() {
    return ( this->getFlagsTCP() & 2 );
}

bool libNetwork::TCPv4packet::isFIN() {
    return ( this->getFlagsTCP() & 1 );
}

bool libNetwork::TCPv4packet::isOption() {
    return ( this->getHeaderLength() > TCP_STANDARD );
}

/* UDP */

libNetwork::UDPv4packet::UDPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

uint16_t libNetwork::UDPv4packet::getSenderPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( UDP_OFFSET, 2 ) );
    convert>>std::hex>>port;
    return port;
}

uint16_t libNetwork::UDPv4packet::getTargetPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( UDP_OFFSET+2, 2 ) );
    convert>>std::hex>>port;
    return port;
}

/* UNKNOWN */

libNetwork::UnknownPacket::UnknownPacket ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}
