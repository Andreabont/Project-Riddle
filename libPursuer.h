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
#include <string>
#include <boost/asio.hpp>
#include <boost/concept_check.hpp>
#include "libAddress.h"
#include "libPacket.h"

/** Class for managing TCP flow. */
class stream
{
private:
    long int timeEpoch;
    int timeMillis;
    
    bool flagFirstFIN;
    bool flagSecondFIN;
    
    mac_address first_mac;
    boost::asio::ip::address first_ip;
    unsigned int first_port;
    unsigned int first_sn;
    std::list<TCPv4packet*> first_buffer;
    std::string first_flow;

    mac_address second_mac;
    boost::asio::ip::address second_ip;
    unsigned int second_port;
    unsigned int second_sn;
    std::list<TCPv4packet*> second_buffer;
    std::string second_flow;
   
public:
  
    stream(TCPv4packet *SYN);
    
    bool streamSynAck(TCPv4packet *SYN);
    
    bool addPacket(TCPv4packet *newPacket);
    
    void flushFirstBuffer();
    void flushSecondBuffer();
  
    long int getTimeEpoch();
    int getTimeMillis();
    mac_address getFirstMacAddress();
    mac_address getSecondMacAddress();
    boost::asio::ip::address getFirstIpAddress();
    boost::asio::ip::address getSecondIpAddress();
    unsigned int getFirstPort();
    unsigned int getSecondPort();
    unsigned int getFirstSN();
    unsigned int getSecondSN();
    std::string exportFlow();
    bool isFIN();
    
};

#endif //LIBPURSUER_H
