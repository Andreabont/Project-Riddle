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

packet::packet(long int timeEpoch_i, int timeMillis_i, std::string rawData_i)
{
  rawData = new std::string;
  *rawData = rawData_i;
  pkgLength = rawData_i.length() / 2;
  timeEpoch = timeEpoch_i;
  timeMillis = timeMillis_i;
  return;
}

packet::~packet()
{
  delete[] rawData;
  return;
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
  
  if(string_cursor + read_byte > this->getLenght()){} // Eccezione di overflow.TODO;
  
  for(int i = string_cursor * 2; i < read_byte * 2; i++)
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

ipv4_address packet::getIPv4Address(int string_cursor)
{
  ipv4_address ipv4_temp(this->getHexString(string_cursor, 4));
  return ipv4_temp;
}

ethernet_header packet::getEthernetHeader()
{
  ethernet_header header_temp;
  
  header_temp.mac_dst() = this->getMacAddress(0);
  header_temp.mac_src() = this->getMacAddress(6);
  
  std::stringstream convert ( this->getHexString(12, 2) );
  convert>>std::hex>>header_temp.protocol_type;
  
  return header_temp;  
}

arp_header packet::getArpHeader()
{
  if(!this->isArp()){} // TODO eccezione non ARP

  arp_header header_temp;
  
  header_temp.mac_dst() = this->getMacAddress(32);
  header_temp.mac_src() = this->getMacAddress(22);
  
  header_temp.ip_dst() = this->getIPv4Address(38);
  header_temp.ip_src() = this->getIPv4Address(28);
  
  std::stringstream convert ( this->getHexString(16, 2) );
  convert>>std::hex>>header_temp.protocol_type;
  
  std::stringstream convert2 ( this->getHexString(20, 2) );
  convert2>>std::hex>>header_temp.opcode;
  
  return header_temp;
}

ipv4_header packet::getIPv4Header()
{
  if(!this->isIPv4()){} // TODO eccezione non ARP

  ipv4_header header_temp;
  
  header_temp.ip_dst() = this->getIPv4Address(30);
  header_temp.ip_src() = this->getIPv4Address(26);
  
  std::stringstream convert ( this->getHexString(23, 1) );
  convert>>std::hex>>header_temp.protocol_type;

  return header_temp;
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
