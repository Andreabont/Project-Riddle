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

        /**
         * Return the first char stream.
         */
        std::string getFirstCharStream();

        /**
         * Return the second char stream.
         */
        std::string getSecondCharStream();

        /** return epoch */
        uint64_t getTimeEpoch();

        /** return milliseconds after epoch */
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
        uint64_t getFirstBufferLength();
        uint64_t getSecondBufferLength();

        /* Ritorna lunghezza in byte dei due flussi in uscita */
        uint64_t getFlowLength();

        std::string exportFlow();
        bool firstFIN();
        bool secondFIN();

    };

}

#endif // CLASSFLOW_H
