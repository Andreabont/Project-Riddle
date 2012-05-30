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
#include "../commons/libAddress.h"
#include "../commons/libPacket.h"

std::string decodeHexText(std::string raw);

/** Class for managing TCP flow. */
class stream
{
private:
    uint64_t timeEpoch;
    uint32_t timeMillis;
    
    bool flagFirstFIN;
    bool flagSecondFIN;
    
    mac_address macAddress[2];
    boost::asio::ip::address ipAddress[2];
    uint16_t port[2];
    
    std::list<TCPv4packet*> buffer[2];
    uint32_t sequenceNumber[2];
    std::string flow[2];
    
    void flushBuffer(int number);
   
public:
    
    bool factory(TCPv4packet *packet);
    
    bool addPacket(TCPv4packet *newPacket);
    
    void flushFirstBuffer();
    void flushSecondBuffer();
  
    uint64_t getTimeEpoch();
    uint32_t getTimeMillis();
    mac_address getFirstMacAddress();
    mac_address getSecondMacAddress();
    boost::asio::ip::address getFirstIpAddress();
    boost::asio::ip::address getSecondIpAddress();
    uint16_t getFirstPort();
    uint16_t getSecondPort();
    uint32_t getFirstSN();
    uint32_t getSecondSN();
    
    /* Ritorna in byte la somma dei payload dei pachetti nel buffer */
    uint64_t getBufferLength();
    
    /* Ritorna lunghezza in byte dei due flussi in uscita */
    uint64_t getFlowLength();
    
    std::string exportFlow();
    std::string exportRawFlow();
    bool isFIN();
    
};

#endif //LIBPURSUER_H
