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

int packet::getLength()
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

    if (string_cursor + read_byte > this->getLength()) throw Overflow();

    for (int i = string_cursor * 2; i < (string_cursor * 2) + (read_byte * 2); i++)
    {
        temp += rawData[i];
    }

    return temp;
}

std::string packet::decodeIPaddress(int string_cursor)
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

int packet::getEtherType()
{
    int protocol_type;

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

int ARPpacket::getOpCode()
{
    int opcode;

    std::stringstream convert (this->getHexString(ARP_OFFSET+6, 2));
    convert>>std::hex>>opcode;

    return opcode;
}


boost::asio::ip::address ARPpacket::getSenderIp()
{
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->decodeIPaddress(ARP_OFFSET+14));
    return newaddr;
}

boost::asio::ip::address ARPpacket::getTargetIp()
{
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->decodeIPaddress(ARP_OFFSET+24));
    return newaddr;
}

/* IPV4 */

packet* IPv4packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    int protocol_type;

    std::string temp;
    temp.reserve(2);

    for (int i = 47; i <= 48; i++)
    {
        temp += rawData_i[i];
    }
    std::stringstream convert ( temp );
    convert>>std::hex>>protocol_type;

    packet *p;
    if (protocol_type == IPV4_TYPE_TCP)
    {

        p = TCPv4packet::factory(timeEpoch_i, timeMillis_i, rawData_i);

    } else if (protocol_type == IPV4_TYPE_UDP)
    {

        p = UDPv4packet::factory(timeEpoch_i, timeMillis_i, rawData_i);

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
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->decodeIPaddress(IPv4_OFFSET+12));
    return newaddr;
}

asio::ip::address IPv4packet::getTargetIp()
{
    boost::asio::ip::address newaddr = boost::asio::ip::address::from_string(this->decodeIPaddress(IPv4_OFFSET+16));
    return newaddr;
}

int IPv4packet::getProtocolType()
{
    int protocol_type;

    std::stringstream convert (this->getHexString(IPv4_OFFSET+9, 1));
    convert>>std::hex>>protocol_type;

    return protocol_type;
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

/* TCP */

packet* TCPv4packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
//TODO
    return new UnknownTCP(timeEpoch_i,timeMillis_i,rawData_i);
}

int TCPv4packet::getSenderPort()
{
    int port;

    std::stringstream convert (this->getHexString(TCP_OFFSET+0, 2));
    convert>>std::hex>>port;

    return port;
}

int TCPv4packet::getTargetPort()
{
    int port;

    std::stringstream convert (this->getHexString(TCP_OFFSET+2, 2));
    convert>>std::hex>>port;

    return port;
}

/* UDP */

packet* UDPv4packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
//TODO
    return new UnknownUDP(timeEpoch_i,  timeMillis_i,  rawData_i);
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

/* UNKNOWN TCP */

UnknownTCP::UnknownTCP(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}

/* UNKNOWN UDP */

UnknownUDP::UnknownUDP(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    rawData = rawData_i;
    pkgLength = rawData_i.length() / 2;
    return;
}
