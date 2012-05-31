/**
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 * 
 * Name        :  Project Riddle
 * Author      :  Andrea Bontempi
 * Version     :  0.1 aplha
 * Description :  Modular Network Sniffer
 * 
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 * 
 * This file is part of the project Riddle.
 *
 *  Foobar is free software: you can redistribute it and/or modify
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
    
    libNetwork::mac_address macAddress[2];
    boost::asio::ip::address ipAddress[2];
    uint16_t port[2];
    
    std::list<libNetwork::TCPv4packet*> buffer[2];
    uint32_t sequenceNumber[2];
    std::string flow[2];
    
    void flushBuffer(int number);
   
public:
    
    bool factory(libNetwork::TCPv4packet *packet);
    
    bool addPacket(libNetwork::TCPv4packet *newPacket);
    
    void flushFirstBuffer();
    void flushSecondBuffer();
  
    uint64_t getTimeEpoch();
    uint32_t getTimeMillis();
    libNetwork::mac_address getFirstMacAddress();
    libNetwork::mac_address getSecondMacAddress();
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
