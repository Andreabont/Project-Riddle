//============================================================================
// Name        : Riddle
// Author      : Andrea Bontempi
// Version     : 0.1SO
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
#include "libPacket.h"
#include "libAddress.h"

/* PACKET */

static packet* packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
  
  int protocol_type;
  
  std::string temp;
  temp.reserve(4);
  
  for(int i = 24; i <= 27; i++)
  {
    temp += rawData_i[i];
  }
  std::stringstream convert ( temp );
  convert>>std::hex>>protocol_type;
  
  if(protocol_type == ETHER_TYPE_ARP)
  {
    
    packet = new ARPpacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    
  } else if(protocol_type == ETHER_TYPE_IPV4)
  {
    
    packet = IPv4packet.factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    
  } else {
    
    packet = new UnknownPacket(); 
    
  }
  
  return packet;
}

int packet::getLenght()
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
  
  if(string_cursor + read_byte > this->getLenght()) throw Overflow();
  
  for(int i = string_cursor * 2; i < (string_cursor * 2) + (read_byte * 2); i++)
  {
    temp += rawData[i];
  }
  
  return temp;
}

mac_address packet::getMacAddress(int string_cursor)
{  
  mac_address mac_temp(this->getHexString(string_cursor, 6));
  return mac_temp;
}

bool packet::isArp()
{
  int protocol_type;
  
  std::stringstream convert ( this->getHexString(12, 2) );
  convert>>std::hex>>protocol_type;
  
  return (protocol_type == ETHER_TYPE_ARP);
}

bool packet::isIPv4()
{
  int protocol_type;
  
  std::stringstream convert ( this->getHexString(12, 2) );
  convert>>std::hex>>protocol_type;
  
  return (protocol_type == ETHER_TYPE_IPV4);
}

bool packet::isIPv6()
{
  int protocol_type;
  
  std::stringstream convert ( this->getHexString(12, 2) );
  convert>>std::hex>>protocol_type;
  
  return (protocol_type == ETHER_TYPE_IPV6);
}

/* ARP */

ARPpacket::ARPpacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i): packet(timeEpoch_i, timeMillis_i, rawData_i)
{
  timeEpoch = timeEpoch_i;
  timeMillis = timeMillis_i;
  rawData = rawData_i;
  return;
}

int ARPpacket::getOpCode()
{
  int opcode;
  
  std::stringstream convert ( this->getHexString(ARP_OFFSET, 2) );
  convert>>std::hex>>opcode;
  
  return opcode;
}

boost::asio::ip::address ARPpacket::getSenderIp()
{
  //TODO
}

mac_address ARPpacket::getSenderMac()
{
  //TODO
}

boost::asio::ip::address ARPpacket::getTargetIp()
{
  //TODO
}

mac_address ARPpacket::getTargetMac()
{
  //TODO
}

/* IPV4 */

packet* IPv4packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
//TODO
packet = new UnknownPacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
return packet;
}

/* TCP */

packet* TCPv4packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
//TODO
packet = new UnknownTCP(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
return packet;
}

/* UDP */

packet* UDPv4packet::factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
//TODO
packet = new UnknownUDP(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
return packet;
}

/* UNKNOWN */

UnknownPacket::UnknownPacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i): packet(timeEpoch_i, timeMillis_i, rawData_i)
{
  timeEpoch = timeEpoch_i;
  timeMillis = timeMillis_i;
  rawData = rawData_i;
  return;
}

/* UNKNOWN TCP */

UnknownTCP::UnknownTCP(int timeEpoch_i, int timeMillis_i, std::string rawData_i): TCPv4packet(timeEpoch_i, timeMillis_i, rawData_i)
{
  timeEpoch = timeEpoch_i;
  timeMillis = timeMillis_i;
  rawData = rawData_i;
  return;
}

/* UNKNOWN UDP */

UnknownUDP::UnknownUDP(int timeEpoch_i, int timeMillis_i, std::string rawData_i): TCPv4packet(timeEpoch_i, timeMillis_i, rawData_i)
{
  timeEpoch = timeEpoch_i;
  timeMillis = timeMillis_i;
  rawData = rawData_i;
  return;
}
