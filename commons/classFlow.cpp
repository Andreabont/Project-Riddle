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

#include <stdint.h>
#include <boost/asio.hpp>
#include "classFlow.h"
#include "classMacAddress.h"
#include "classPacket.h"

bool libNetwork::stream::factory ( libNetwork::TCPv4packet *packet ) {

    if ( packet->isSYN() ) {

        if ( !packet->isACK() ) {

            timeEpoch = packet->getEpoch();
            timeMillis = packet->getMillis();
            macAddress[0] = packet->getSenderMac();
            macAddress[1] = packet->getTargetMac();
            ipAddress[0] = packet->getSenderIp();
            ipAddress[1] = packet->getTargetIp();
            port[0] = packet->getSenderPort();
            port[1] = packet->getTargetPort();
            sequenceNumber[0] = packet->getSequenceNumber();
            sequenceNumber[1] = 0;
            flagFirstFIN = false;
            flagSecondFIN = false;

            delete packet;
            return true;

        } else {

            if ( sequenceNumber[0] + 1 == packet->getAcknowledgmentNumber() ) {
                sequenceNumber[1] = packet->getSequenceNumber();
                delete packet;
                return true;
            }

        }

    }

    delete packet;
    return false;

}

void libNetwork::stream::factory ( std::string packet ) {

}

bool libNetwork::stream::addPacket ( libNetwork::TCPv4packet *newPacket ) {

    using namespace std;

    int a,b;

    if ( !newPacket->isSYN() ) {

        if ( newPacket->getSenderPort() == port[0] ) {

            // Siamo nel primo buffer

            a = 1;
            b = 0;

        } else if ( newPacket->getSenderPort() == port[1] ) {
            // Siamo nel secondo buffer

            a = 0;
            b = 1;

        } else return false; // Buffer non identificato.


        if ( newPacket->isACK() ) { // Se c'è ACK setto il flag sul pacchetto corrispondente, se c'è.

            for ( list<libNetwork::TCPv4packet*>::iterator it = buffer[a].begin(); it != buffer[a].end(); it++ ) {

                if ( ( *it )->getSequenceNumber() == newPacket->getAcknowledgmentNumber() - ( ( *it )->getPayLoad().size() /2 ) ) {
                    ( *it )->public_flag = true;
                    break;
                }
            }

        }

        if ( newPacket->getPayLoad().size() != 0 ) { // Salvo il pacchetto solo se ha del payload.
            buffer[b].push_back ( newPacket );
        }

        return true;
    }

    return false;

}

void libNetwork::stream::flushBuffer ( int number ) {
    bool isFound;

    do {

        isFound = false;

        for ( std::list<libNetwork::TCPv4packet*>::iterator it = buffer[number].begin(); it != buffer[number].end(); it++ ) {
            if ( sequenceNumber[number] + 1 == ( *it )->getSequenceNumber() && ( *it )->public_flag ) {
                std::string payload = ( *it )->getPayLoad();
                flow[number] += payload;
                sequenceNumber[number] += payload.size() /2; // unsigned, si azzera come avviene nel tcp.
                buffer[number].remove ( *it );
                isFound = true;
                break;
            }
        }

    } while ( isFound );

}

void libNetwork::stream::flushFirstBuffer() {
    flushBuffer ( 0 );
}

void libNetwork::stream::flushSecondBuffer() {
    flushBuffer ( 1 );
}


std::string libNetwork::stream::exportFlow() {
    std::stringstream stdstring;
    stdstring << timeEpoch << "!" << timeMillis << "!";
    stdstring << macAddress[0].to_string() << "!" << macAddress[1].to_string() << "!";
    stdstring << ipAddress[0].to_string() << "!" << ipAddress[1].to_string() << "!";
    stdstring << port[0] << "!" << port[1] << "!";
    stdstring << flow[0] << "!" << flow[1];
    return stdstring.str();;
}

uint64_t libNetwork::stream::getBufferLength() {

    uint64_t bufferlenght = 0;

    for ( int i = 0; i <= 1; i++ ) {

        for ( std::list<libNetwork::TCPv4packet*>::iterator it = buffer[i].begin(); it != buffer[i].end(); it++ ) {

            bufferlenght += ( *it )->getPayloadLength();

        }

    }

    return bufferlenght;
}

uint64_t libNetwork::stream::getFlowLength() {
    return ( flow[0].length() + flow[1].length() ) /2;
}

uint64_t libNetwork::stream::getTimeEpoch() {
    return timeEpoch;
}

uint32_t libNetwork::stream::getTimeMillis() {
    return timeMillis;
}

libNetwork::mac_address libNetwork::stream::getFirstMacAddress() {
    return macAddress[0];
}

libNetwork::mac_address libNetwork::stream::getSecondMacAddress() {
    return macAddress[1];
}

boost::asio::ip::address libNetwork::stream::getFirstIpAddress() {
    return ipAddress[0];
}

boost::asio::ip::address libNetwork::stream::getSecondIpAddress() {
    return ipAddress[1];
}

uint16_t libNetwork::stream::getFirstPort() {
    return port[0];
}

uint16_t libNetwork::stream::getSecondPort() {
    return port[1];
}

uint32_t libNetwork::stream::getFirstSN() {
    return sequenceNumber[0];
}

uint32_t libNetwork::stream::getSecondSN() {
    return sequenceNumber[1];
}

bool libNetwork::stream::isFIN() {
    return flagFirstFIN && flagSecondFIN;
}

std::string libNetwork::stream::getFirstBuffer() {
    return flow[0];
}

std::string libNetwork::stream::getSecondBuffer() {
    return flow[1];
}
