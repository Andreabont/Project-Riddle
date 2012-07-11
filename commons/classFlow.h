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
 *  The project Riddle is free software: you can redistribute it and/or modify
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


#ifndef CLASSFLOW_H
#define CLASSFLOW_H

#include <stdint.h>
#include <list>
#include <string>
#include <boost/asio.hpp>
#include "classMacAddress.h"
#include "classPacket.h"

namespace libNetwork {

/** Class for managing TCP flow. */
class stream
{
private:
    uint64_t timeEpoch;
    uint32_t timeMillis;

    libNetwork::mac_address macAddress[2];
    boost::asio::ip::address ipAddress[2];
    uint16_t port[2];

    std::map<uint32_t, libNetwork::TCPv4packet*> snBuffer[2];
    std::map<uint32_t, libNetwork::TCPv4packet*> ackExpBuffer[2];
    uint32_t snPointer[2];

    std::string charStream[2];

    bool fluxFIN[2];

    void flushBuffer ( int number );
    void delPacket ( uint32_t sn, int bufferNumber );

public:
    /** Initialize flow with the first packet of the TCP handshake (SYN) */
    bool factory ( libNetwork::TCPv4packet *packet );

    /** Initialize flow with string (classFlow protocol) */
    void factory ( std::string flow );


    /** Put new packet in the flow */
    bool addPacket ( libNetwork::TCPv4packet *newPacket );

    /**
     * Read the first packet buffer and save the payload in the first char stream.
     * Stop if the flow is interrupted.
     */
    void flushFirstBuffer();

    /**
     * Read the second packet buffer and save the payload in the second char stream.
     * Stop if the flow is interrupted.
     */
    void flushSecondBuffer();

    /** return the first char stream. */
    std::string getFirstCharStream();

    /** return the second char stream. */
    std::string getSecondCharStream();

    /** return epoch */
    uint64_t getTimeEpoch();

    /** return milliseconds after epoch */
    uint32_t getTimeMillis();

    /** return first mac address */
    libNetwork::mac_address getFirstMacAddress();

    /** return second mac address */
    libNetwork::mac_address getSecondMacAddress();

    /** return first ip address */
    boost::asio::ip::address getFirstIpAddress();

    /** return second ip address */
    boost::asio::ip::address getSecondIpAddress();
    
    /** return first port */
    uint16_t getFirstPort();
    
    /** return second port */
    uint16_t getSecondPort();
    
    /** return first sn */
    uint32_t getFirstSN();
    
    /** return second sn */
    uint32_t getSecondSN();

    /** return the sum in bytes of the contents of the payload in the first buffer */
    uint64_t getFirstBufferLength();
    
    /** return the sum in bytes of the contents of the payload in the second buffer */
    uint64_t getSecondBufferLength();

    /** returns length in bytes of the two output streams */
    uint64_t getFlowLength();
    
    /** export formatted flow */
    std::string exportFlow();
    
    /** true if the first flow have FIN or RST packet */
    bool firstFIN();
    
    /** true if the second flow have FIN or RST packet */
    bool secondFIN();

};

}

#endif // CLASSFLOW_H
