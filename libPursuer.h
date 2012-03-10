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

#ifndef LIBPURSUER_H
#define LIBPURSUER_H

#include <list>
#include <boost/asio.hpp>
#include "libAddress.h"
#include "libPacket.h"

class stream
{
private:
    long int timeEpoch;
    int timeMillis;
    
    bool flagFull;
    
    mac_address first_mac;
    boost::asio::ip::address first_ip;
    unsigned int first_port;
    std::list<TCPv4packet*> first_flow;

    mac_address second_mac;
    boost::asio::ip::address second_ip;
    unsigned int second_port;
    std::list<TCPv4packet*> second_flow;
   
public:
  
    stream(long int timeEpoch_i, int timeMillis_i);
    
    bool addPacket(TCPv4packet *newPacket);
  
    long int getTimeEpoch();
    int getTimeMillis();
    mac_address getFirstMacAddress();
    mac_address getSecondMacAddress();
    boost::asio::ip::address getFirstIpAddress();
    boost::asio::ip::address getSecondIpAddress();
    unsigned int getFirstPort();
    unsigned int getSecondPort();
    bool isFull();
};

#endif //LIBPURSUER_H
