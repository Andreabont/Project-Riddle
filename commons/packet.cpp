/**
* - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
*
* Name        :  Project Riddle
* Author      :  Andrea Bontempi
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
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <ios>
#include <map>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "macaddress.h"
#include "packet.h"

/* PACKET */

std::shared_ptr<network::packet> network::packet::factory ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {

    uint16_t protocol_type;

    std::string temp;
    temp.reserve ( 4 );

    for ( int i = 24; i <= 27; i++ ) {
        temp += rawData_i[i];
    }
    std::stringstream convert ( temp );
    convert>>std::hex>>protocol_type;

    packet *p;
    if ( protocol_type == ethertype::ARP ) {

        p = new ARPpacket ( timeEpoch_i, timeMillis_i, rawData_i );

    } else if ( protocol_type == ethertype::IPV4 ) {

        p = IPv4packet::factory ( timeEpoch_i, timeMillis_i, rawData_i );

    } else {

        p = new UnknownPacket ( timeEpoch_i, timeMillis_i, rawData_i );

    }

    return std::shared_ptr<packet>(p);
}

std::shared_ptr<network::packet> network::packet::factory ( std::string packetLine ) {
    std::vector< std::string > section;
    boost::algorithm::split ( section, packetLine, boost::algorithm::is_any_of ( "!" ) );

    std::shared_ptr<network::packet> pkg = packet::factory ( boost::lexical_cast<int> ( section[0] ), boost::lexical_cast<int> ( section[1] ), section[2] );

    return pkg;
}

uint32_t network::packet::getPacketLength() {
    return pkgLength;
}

uint64_t network::packet::getEpoch() {
    return timeEpoch;
}

uint32_t network::packet::getMillis() {
    return timeMillis;
}

uint32_t network::packet::getLength()
{
    return pkgLength;
}

inline std::string network::packet::getHexString ( int string_cursor, int read_byte ) throw(Overflow) {
    std::string temp;
    temp.reserve ( read_byte * 2 );

    if ( string_cursor + read_byte > this->getPacketLength() ) throw Overflow();

    for ( int i = string_cursor * 2; i < ( string_cursor * 2 ) + ( read_byte * 2 ); i++ ) {
        temp += rawData[i];
    }

    return temp;
}

inline std::string network::packet::getDecimalIP ( int string_cursor ) throw (Overflow) {
    std::string temp;
    std::string stamp;
    temp.reserve ( 2 );

    for ( int i=0; i <= 7; i++ ) {
        temp += rawData[ ( string_cursor*2 ) +i];
        if (i&0x01) { // False if "i" is even
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

inline network::mac_address network::packet::getMacAddress ( int string_cursor ) throw (Overflow) {
    mac_address mac_temp ( this->getHexString ( string_cursor, 6 ) );
    return mac_temp;
}

network::mac_address network::packet::getSenderMac() {
    return this->getMacAddress ( 6 );
}

network::mac_address network::packet::getTargetMac() {
    return this->getMacAddress ( 0 );
}

uint16_t network::packet::getEtherType() {
    uint16_t protocol_type;

    std::stringstream convert ( this->getHexString ( 12, 2 ) );
    convert>>std::hex>>protocol_type;

    return protocol_type;
}


/* ARP */

network::ARPpacket::ARPpacket ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {

    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

uint16_t network::ARPpacket::getOpCode() {
    uint16_t opcode;

    std::stringstream convert ( this->getHexString ( offset::ARP + 6, 2 ) );
    convert>>std::hex>>opcode;

    return opcode;
}


boost::asio::ip::address network::ARPpacket::getSenderIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( offset::ARP + 14 ) );
    return newaddr;
}

boost::asio::ip::address network::ARPpacket::getTargetIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( offset::ARP + 24 ) );
    return newaddr;
}

/* IPV4 */

network::packet* network::IPv4packet::factory ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    uint16_t protocol_type;

    std::string temp;
    temp.reserve ( 2 );

    for ( int i = 46; i <= 47; i++ ) {
        temp += rawData_i[i];
    }
    std::stringstream convert ( temp );
    convert>>std::hex>>protocol_type;

    packet *p;
    if ( protocol_type == ipv4type::TCP ) {

        p = new TCPv4packet ( timeEpoch_i, timeMillis_i, rawData_i );

    } else if ( protocol_type == ipv4type::UDP ) {

        p = new UDPv4packet ( timeEpoch_i, timeMillis_i, rawData_i );

    } else if ( protocol_type == ipv4type::ICMP ) {

        p = new ICMPv4packet ( timeEpoch_i, timeMillis_i, rawData_i );

    } else {

        p = new UnknownPacket ( timeEpoch_i, timeMillis_i, rawData_i );

    }

    return p;
}

boost::asio::ip::address network::IPv4packet::getSenderIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( offset::IPV4 + 12 ) );
    return newaddr;
}

boost::asio::ip::address network::IPv4packet::getTargetIp() {
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string ( this->getDecimalIP ( offset::IPV4 + 16 ) );
    return newaddr;
}

uint16_t network::IPv4packet::getIdentity() {
    uint16_t id;

    std::stringstream convert ( this->getHexString ( offset::IPV4 + 4, 2 ) );
    convert>>std::hex>>id;

    return id;
}

uint16_t network::IPv4packet::getTTL() {
    uint16_t ttl;

    std::stringstream convert ( this->getHexString ( offset::IPV4 + 8, 1 ) );
    convert>>std::hex>>ttl;

    return ttl;
}

uint16_t network::IPv4packet::getProtocolType() {
    uint16_t protocol_type;

    std::stringstream convert ( this->getHexString ( offset::IPV4 + 9, 1 ) );
    convert>>std::hex>>protocol_type;

    return protocol_type;
}

uint16_t network::IPv4packet::getIPChecksum() {
    uint16_t cs;
    std::stringstream convert ( this->getHexString ( offset::IPV4 + 10, 2 ) );
    convert>>std::hex>>cs;
    return cs;
}

bool network::IPv4packet::verifyIPChecksum() {

    int sum = 0;

    for ( int i = 0; i < 20; i += 2 ) {

        short unsigned int temp;
        std::stringstream convert ( this->getHexString ( offset::IPV4 + i, 2 ) );
        convert >> std::hex >> temp;
        sum += temp;

    }

    return ( ( sum & 0xFFFF ) + ( sum >>= 16 ) == 0xFFFF );
}

int network::IPv4packet::getFlagsIP() {
    int flag;
    std::stringstream convert ( this->getHexString ( offset::IPV4 + 6, 1 ) );
    convert>>std::hex>>flag;
    return flag;
}

/* ICMP */

network::ICMPv4packet::ICMPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

uint16_t network::ICMPv4packet::getMessageType() {
    uint16_t  message_type;

    std::stringstream convert ( this->getHexString ( offset::ICMPV4, 2 ) );
    convert>>std::hex>>message_type;

    return message_type;
}

/* TCP */

network::TCPv4packet::TCPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    public_flag = false;
    return;
}

uint16_t network::TCPv4packet::getSenderPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( offset::TCP, 2 ) );
    convert>>std::hex>>port;
    return port;
}

uint16_t network::TCPv4packet::getTargetPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( offset::TCP + 2, 2 ) );
    convert>>std::hex>>port;
    return port;
}

uint32_t network::TCPv4packet::getSequenceNumber() {
    uint32_t sn;
    std::stringstream convert ( this->getHexString ( offset::TCP + 4, 4 ) );
    convert>>std::hex>>sn;
    return sn;
}

uint32_t network::TCPv4packet::getAcknowledgmentNumber() {
    uint32_t an;
    std::stringstream convert ( this->getHexString ( offset::TCP + 8, 4 ) );
    convert>>std::hex>>an;
    return an;
}

uint32_t network::TCPv4packet::getExpectedAcknowledgmentNumber() {
    return this->getSequenceNumber() + this->getPayloadLength();
}

unsigned int network::TCPv4packet::getHeaderLength() {
    /*
     * Sono utilizzati solo i primi 8 bit del byte, necessita traslazione.
     * Indica i gruppi da 32 bit contenuti, necessita conversione.
     */
    unsigned int hl;
    std::stringstream convert ( this->getHexString ( offset::TCP + 12, 1 ) );
    convert>>std::hex>>hl;
    hl >>= 4;
    hl = ( hl * 32 ) / 8;
    return hl;
}

unsigned int network::TCPv4packet::getPayloadLength() {
    return ( this->getPayLoad().length() ) /2;
}

int network::TCPv4packet::getFlagsTCP() {
    int flag;
    std::stringstream convert ( this->getHexString ( offset::TCP + 13, 1 ) );
    convert>>std::hex>>flag;
    return flag;
}

unsigned int network::TCPv4packet::getWindowSize() {
    unsigned int ws;
    std::stringstream convert ( this->getHexString ( offset::TCP + 14, 2 ) );
    convert>>std::hex>>ws;
    return ws;
}

unsigned int network::TCPv4packet::getTCPChecksum() {
    unsigned int cs;
    std::stringstream convert ( this->getHexString ( offset::TCP + 16, 2 ) );
    convert>>std::hex>>cs;
    return cs;
}

unsigned int network::TCPv4packet::getUrgentPointer() {
    unsigned int up;
    std::stringstream convert ( this->getHexString ( offset::TCP + 18, 2 ) );
    convert>>std::hex>>up;
    return up;
}

std::string network::TCPv4packet::getOptionRaw() {
    return this->getHexString ( offset::TCP + TCP_STANDARD, this->getHeaderLength() - TCP_STANDARD );
}

std::map< int, std::string > network::TCPv4packet::getOptionMap() {
    std::map<int, std::string> tempMap;
    if ( this->isOption() && !this->isSYN() ) { // FIXME - SYN usa altro protocollo???
        for ( int i=0; i < ( this->getHeaderLength() - TCP_STANDARD ); i++ ) {
            int read;
            std::stringstream convert ( this->getHexString ( offset::TCP + TCP_STANDARD+i, 1 ) );
            convert >> std::hex >> read;

            if ( read != 1 ) {
                std::stringstream convert2 ( this->getHexString ( offset::TCP + TCP_STANDARD+i+1, 1 ) );
                int optionLength;
                convert2 >> std::hex >> optionLength;
                tempMap[read] = this->getHexString ( offset::TCP + TCP_STANDARD+i+2, optionLength-2 );
                i += optionLength;
            }
        }
    }
    return tempMap;
}

std::string network::TCPv4packet::getPayLoad() {
    int size = this->getHeaderLength();
    int start = offset::TCP + size;
    return this->getHexString ( start, size - start );
}

/* UDP */

network::UDPv4packet::UDPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

uint16_t network::UDPv4packet::getSenderPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( offset::UDP, 2 ) );
    convert>>std::hex>>port;
    return port;
}

uint16_t network::UDPv4packet::getTargetPort() {
    uint16_t port;
    std::stringstream convert ( this->getHexString ( offset::UDP + 2, 2 ) );
    convert>>std::hex>>port;
    return port;
}

std::string network::UDPv4packet::getPayLoad() {
    int start = offset::UDP + 64;
    int paylen = this->getLength() - start;
    if(paylen <= 0) return ""; // FIXME
    return this->getHexString ( start, paylen );
}

/* UNKNOWN */

network::UnknownPacket::UnknownPacket ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i ) {
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}
