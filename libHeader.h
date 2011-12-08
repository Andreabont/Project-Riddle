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

#ifndef LIBHEADER_H
#define LIBHEADER_H

#include <string>
#include "libAddress.h"

/* Class for managing Ethernet Header */
class ethernet_header
{
  public:
  mac_address mac_dst;
  mac_address mac_src;
  short int protocol_type;
  
  void getMacAddress(std::string);
  void getProtocolType(std::string);
};

/* Class for managing ARP Header */
class arp_header
{
  public:
  mac_address mac_dst;
  mac_address mac_src;
  ipv4_address ip_dst;
  ipv4_address ip_src;
  short int protocol_type;
  short int opcode;
  
  void getMacAddress(std::string);
  void getIpAddress(std::string);
  void getProtocolType(std::string);
  void getOpcode(std::string);
};

class ipv4_header
{
  public:
  ipv4_address ip_dst;
  ipv4_address ip_src;
  short int protocol_type;
  
  void getIpAddress(std::string);
  void getProtocolType(std::string);
};

#endif //LIBHEADER_H