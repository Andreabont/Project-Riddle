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

std::string decodeHexText(std::string raw);

/** Class for managing TCP flow. */
class stream
{
private:
    long int timeEpoch;
    int timeMillis;
    
    bool flagFirstFIN;
    bool flagSecondFIN;
    
    mac_address macAddress[2];
    boost::asio::ip::address ipAddress[2];
    unsigned int port[2];
    
    std::list<TCPv4packet*> buffer[2];
    unsigned int sequenceNumber[2];
    std::string flow[2];
    
    void flushBuffer(int number);
   
public:
    
    bool factory(TCPv4packet *packet);
    
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
    std::string exportRawFlow();
    bool isFIN();
    
};

#endif //LIBPURSUER_H
