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

#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <ios>
#include <map>
#include <boost/lexical_cast.hpp>
#include "libPacket.h"
#include "libAddress.h"

/* PACKET */

using namespace boost;

packet* packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{

    int protocol_type;

    std::string temp;
    temp.reserve(4);

    for (int i = 24; i <= 27; i++)
    {
        temp += rawData_i[i];
    }
    std::stringstream convert ( temp );
    convert>>std::hex>>protocol_type;

    packet *p;
    if (protocol_type == ETHER_TYPE_ARP)
    {

        p = new ARPpacket(timeEpoch_i, timeMillis_i, rawData_i);

    } else if (protocol_type == ETHER_TYPE_IPV4)
    {

        p = IPv4packet::factory(timeEpoch_i, timeMillis_i, rawData_i);

    } else {

        p = new UnknownPacket(timeEpoch_i, timeMillis_i, rawData_i);

    }

    return p;
}


int packet::getPacketLength()
{
    return pkgLength;
}

long int packet::getEpoch()
{
    return timeEpoch;
}

int packet::getMillis()
{
    return timeMillis;
}

std::string packet::getHexString(int string_cursor, int read_byte)
{
    std::string temp;
    temp.reserve(read_byte * 2);

    if (string_cursor + read_byte > this->getPacketLength()) throw Overflow();

    for (int i = string_cursor * 2; i < (string_cursor * 2) + (read_byte * 2); i++)
    {
        temp += rawData[i];
    }

    return temp;
}

std::string packet::getDecimalIP(int string_cursor)
{
    std::string temp;
    std::string stamp;
    temp.reserve(2);

    for (int i=0; i <= 7; i++)
    {
        temp += rawData[(string_cursor*2)+i];
        if (i%2 != 0)
        {
            std::stringstream convert(temp);
            int a;
            convert>>std::hex>>a;
            stamp += lexical_cast<std::string>(a);
            if (i != 7) stamp += ".";
            temp = "";
        }
    }
    return stamp;
}

mac_address packet::getMacAddress(int string_cursor)
{
    mac_address mac_temp(this->getHexString(string_cursor, 6));
    return mac_temp;
}

bool packet::isArp()
{
    return (this->getEtherType() == ETHER_TYPE_ARP);
}

bool packet::isIPv4()
{
    return (this->getEtherType() == ETHER_TYPE_IPV4);
}

bool packet::isIPv6()
{
    return (this->getEtherType() == ETHER_TYPE_IPV6);
}

mac_address packet::getSenderMac()
{
    return this->getMacAddress(6);
}

mac_address packet::getTargetMac()
{
    return this->getMacAddress(0);
}

unsigned int packet::getEtherType()
{
    unsigned int protocol_type;

    std::stringstream convert (this->getHexString(12, 2));
    convert>>std::hex>>protocol_type;

    return protocol_type;
}


/* ARP */

ARPpacket::ARPpacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{

    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

unsigned int ARPpacket::getOpCode()
{
    unsigned int opcode;

    std::stringstream convert (this->getHexString(ARP_OFFSET+6, 2));
    convert>>std::hex>>opcode;

    return opcode;
}


boost::asio::ip::address ARPpacket::getSenderIp()
{
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->getDecimalIP(ARP_OFFSET+14));
    return newaddr;
}

boost::asio::ip::address ARPpacket::getTargetIp()
{
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->getDecimalIP(ARP_OFFSET+24));
    return newaddr;
}

/* IPV4 */

packet* IPv4packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    int protocol_type;

    std::string temp;
    temp.reserve(2);

    for (int i = 46; i <= 47; i++)
    {
        temp += rawData_i[i];
    }
    std::stringstream convert ( temp );
    convert>>std::hex>>protocol_type;

    packet *p;
    if (protocol_type == IPV4_TYPE_TCP)
    {

        p = new TCPv4packet(timeEpoch_i, timeMillis_i, rawData_i);

    } else if (protocol_type == IPV4_TYPE_UDP)
    {

        p = new UDPv4packet(timeEpoch_i, timeMillis_i, rawData_i);

    } else if (protocol_type == IPV4_TYPE_ICMP)
    {

        p = new ICMPv4packet(timeEpoch_i, timeMillis_i, rawData_i);

    } else {

        p = new UnknownPacket(timeEpoch_i, timeMillis_i, rawData_i);

    }

    return p;
}

asio::ip::address IPv4packet::getSenderIp()
{
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->getDecimalIP(IPv4_OFFSET+12));
    return newaddr;
}

asio::ip::address IPv4packet::getTargetIp()
{
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->getDecimalIP(IPv4_OFFSET+16));
    return newaddr;
}

unsigned int IPv4packet::getIdentity()
{
    unsigned int id;

    std::stringstream convert (this->getHexString(IPv4_OFFSET+4, 2));
    convert>>std::hex>>id;

    return id;
}

unsigned int IPv4packet::getTTL()
{
    unsigned int ttl;

    std::stringstream convert (this->getHexString(IPv4_OFFSET+8, 1));
    convert>>std::hex>>ttl;

    return ttl;
}

unsigned int IPv4packet::getProtocolType()
{
    unsigned int protocol_type;

    std::stringstream convert (this->getHexString(IPv4_OFFSET+9, 1));
    convert>>std::hex>>protocol_type;

    return protocol_type;
}

unsigned int IPv4packet::getIPChecksum()
{
    unsigned int cs;
    std::stringstream convert (this->getHexString(IPv4_OFFSET+10, 2));
    convert>>std::hex>>cs;
    return cs;
}

bool IPv4packet::verifyIPChecksum()
{

    int sum = 0;
    
    for(int i = 0; i < 20; i += 2)
    {
      
      short unsigned int temp;
      std::stringstream convert (this->getHexString(IPv4_OFFSET+i,2));
      convert >> std::hex >> temp;
      sum += temp;
     
    }
     
    return ((sum & 0xFFFF) + (sum >>= 16) == 0xFFFF);
}

bool IPv4packet::isTCP()
{
    return (this->getProtocolType() == IPV4_TYPE_TCP);
}

bool IPv4packet::isUDP()
{
    return (this->getProtocolType() == IPV4_TYPE_UDP);
}

bool IPv4packet::isICMP()
{
    return (this->getProtocolType() == IPV4_TYPE_ICMP);
}

/* ICMP */

ICMPv4packet::ICMPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

unsigned int ICMPv4packet::getMessageType()
{
    unsigned int message_type;

    std::stringstream convert (this->getHexString(ICMPV4_OFFSET, 1));
    convert>>std::hex>>message_type;

    return message_type;
}

unsigned int ICMPv4packet::getMessageCode()
{
    unsigned int message_code;

    std::stringstream convert (this->getHexString(ICMPV4_OFFSET+1, 1));
    convert>>std::hex>>message_code;

    return message_code;
}

/* TCP */

TCPv4packet::TCPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    public_flag = false;
    return;
}

unsigned int TCPv4packet::getSenderPort()
{
    unsigned int port;
    std::stringstream convert (this->getHexString(TCP_OFFSET, 2));
    convert>>std::hex>>port;
    return port;
}

unsigned int TCPv4packet::getTargetPort()
{
    unsigned int port;
    std::stringstream convert (this->getHexString(TCP_OFFSET+2, 2));
    convert>>std::hex>>port;
    return port;
}

unsigned int TCPv4packet::getSequenceNumber()
{
    unsigned int sn;
    std::stringstream convert (this->getHexString(TCP_OFFSET+4, 4));
    convert>>std::hex>>sn;
    return sn;
}

unsigned int TCPv4packet::getAcknowledgmentNumber()
{
    unsigned int an;
    std::stringstream convert (this->getHexString(TCP_OFFSET+8, 4));
    convert>>std::hex>>an;
    return an;
}

unsigned int TCPv4packet::getHeaderLength()
{
    /*
     * Sono utilizzati solo i primi 8 bit del byte, necessita traslazione.
     * Indica i gruppi da 32 bit contenuti, necessita conversione.
     */
    unsigned int hl;
    std::stringstream convert (this->getHexString(TCP_OFFSET+12, 1));
    convert>>std::hex>>hl;
    hl >>= 4;
    hl = (hl * 32) / 8;
    return hl;
}

int TCPv4packet::getFlags()
{
    int flag;
    std::stringstream convert (this->getHexString(TCP_OFFSET+13, 1));
    convert>>std::hex>>flag;
    return flag;
}

unsigned int TCPv4packet::getWindowSize()
{
    unsigned int ws;
    std::stringstream convert (this->getHexString(TCP_OFFSET+14, 2));
    convert>>std::hex>>ws;
    return ws;
}

unsigned int TCPv4packet::getTCPChecksum()
{
    unsigned int cs;
    std::stringstream convert (this->getHexString(TCP_OFFSET+16, 2));
    convert>>std::hex>>cs;
    return cs;
}

bool TCPv4packet::verifyTCPChecksum()
{
    // TODO - Checksum TCP non viene usato???
}

unsigned int TCPv4packet::getUrgentPointer()
{
    unsigned int up;
    std::stringstream convert (this->getHexString(TCP_OFFSET+18, 2));
    convert>>std::hex>>up;
    return up;
}

std::string TCPv4packet::getOptionRaw()
{
    return this->getHexString(TCP_OFFSET + TCP_STANDARD, this->getHeaderLength() - TCP_STANDARD);
}

std::map< int, std::string > TCPv4packet::getOptionMap()
{
    std::map<int, std::string> tempMap;
    if(this->isOption() && !this->isSYN()) // FIXME - SYN usa altro protocollo???
    {
        for(int i=0; i < (this->getHeaderLength() - TCP_STANDARD); i++)
        {
            int read;
            std::stringstream convert ( this->getHexString(TCP_OFFSET+TCP_STANDARD+i, 1) );
            convert >> std::hex >> read;

            if(read != 1)
            {
                std::stringstream convert2 ( this->getHexString(TCP_OFFSET+TCP_STANDARD+i+1, 1) );
                int optionLength;
                convert2 >> std::hex >> optionLength;
                tempMap[read] = this->getHexString(TCP_OFFSET+TCP_STANDARD+i+2, optionLength-2);
                i += optionLength;
            }
        }
    }
    return tempMap;
}

std::string TCPv4packet::getPayLoad()
{
    int start = TCP_OFFSET + this->getHeaderLength();
    return this->getHexString(start, this->getPacketLength() - start);
}

bool TCPv4packet::isCWR()
{
    return (this->getFlags() & 128);
}

bool TCPv4packet::isECE()
{
    return (this->getFlags() & 64);
}

bool TCPv4packet::isURG()
{
    return (this->getFlags() & 32);
}

bool TCPv4packet::isACK()
{
    return (this->getFlags() & 16);
}

bool TCPv4packet::isPSH()
{
    return (this->getFlags() & 8);
}

bool TCPv4packet::isRST()
{
    return (this->getFlags() & 4);
}

bool TCPv4packet::isSYN()
{
    return (this->getFlags() & 2);
}

bool TCPv4packet::isFIN()
{
    return (this->getFlags() & 1);
}

bool TCPv4packet::isOption()
{
    return (this->getHeaderLength() > TCP_STANDARD);
}

/* UDP */

UDPv4packet::UDPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

unsigned int UDPv4packet::getSenderPort()
{
    unsigned int port;
    std::stringstream convert (this->getHexString(UDP_OFFSET, 2));
    convert>>std::hex>>port;
    return port;
}

unsigned int UDPv4packet::getTargetPort()
{
    unsigned int port;
    std::stringstream convert (this->getHexString(UDP_OFFSET+2, 2));
    convert>>std::hex>>port;
    return port;
}

/* UNKNOWN */

UnknownPacket::UnknownPacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}
