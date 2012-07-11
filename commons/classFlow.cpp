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

#include <iostream>
#include <stdint.h>
#include <boost/asio.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <map>
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
            snPointer[0] = packet->getSequenceNumber();
            snPointer[1] = 0;
            fluxFIN[0] = false;
            fluxFIN[1] = false;

            delete packet;
            return true;

        } else {

            if ( snPointer[0] + 1 == packet->getAcknowledgmentNumber() ) {
                snPointer[0]++;
                snPointer[1] = packet->getSequenceNumber() + 1;
                delete packet;
                return true;
            }

        }

    }

    delete packet;
    return false;

}

void libNetwork::stream::factory ( std::string newflow ) {

    std::vector< std::string > section;
    boost::algorithm::split ( section, newflow, boost::algorithm::is_any_of ( "!" ) );

    timeEpoch = boost::lexical_cast<uint64_t> ( section[0] );
    timeMillis = boost::lexical_cast<uint64_t> ( section[1] );
    /* macAddress[0] = new libNetwork::mac_address ( section[2] );
     macAddress[1] = new libNetwork::mac_address ( section[3] );
     ipAddress[0] = ;
     ipAddress[1] = ; */
    port[0] =  boost::lexical_cast<uint16_t> ( section[6] );
    port[1] =  boost::lexical_cast<uint16_t> ( section[7] );
    charStream[0] = section[8];
    charStream[1] = section[9];

}

bool libNetwork::stream::addPacket ( libNetwork::TCPv4packet *newPacket ) {

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


            std::map<uint32_t, libNetwork::TCPv4packet*>::iterator iter = ackExpBuffer[a].find ( newPacket->getAcknowledgmentNumber() );

            if ( iter != ackExpBuffer[a].end() ) {

                ( *iter ).second->public_flag == true;

                uint32_t ackExpToFind = ( *iter ).second->getSequenceNumber();

                bool endLoop = false;

                while ( !endLoop ) {

                    std::map<uint32_t, libNetwork::TCPv4packet*>::iterator subIter = ackExpBuffer[a].find ( ackExpToFind );

                    if ( subIter != ackExpBuffer[a].end() && ( *subIter ).second->public_flag == false ) {

                        ( *subIter ).second->public_flag = true;
                        ackExpToFind = ( *subIter ).second->getSequenceNumber();
                        continue;

                    }

                    endLoop = true;

                }

            } // Non trovato opss XD

        }

        if ( newPacket->getPayloadLength() != 0 ) { // Salvo il pacchetto solo se ha del payload.

            // Sovrascrivo se è ritrasmissione.

            std::map<uint32_t, libNetwork::TCPv4packet*>::iterator searchIter1 = snBuffer[b].find ( newPacket->getSequenceNumber() );
            std::map<uint32_t, libNetwork::TCPv4packet*>::iterator searchIter2 = ackExpBuffer[b].find ( newPacket->getExpectedAcknowledgmentNumber() );

            if(searchIter1 != snBuffer[b].end()) {
                snBuffer[b].erase(searchIter1);
            }

            if(searchIter2 != ackExpBuffer[b].end()) {
                ackExpBuffer[b].erase(searchIter2);
            }

            snBuffer[b][newPacket->getSequenceNumber()] = newPacket;
            ackExpBuffer[b][newPacket->getExpectedAcknowledgmentNumber()] = newPacket;
        }

        if ( newPacket->isFIN() ) {
            fluxFIN[b] = true;
        }

        if ( newPacket->isRST() ) {
            fluxFIN[0] = true;
            fluxFIN[1] = true;
        }

        return true;
    }

    return false;

}

void libNetwork::stream::delPacket ( uint32_t sn, int bufferNumber ) {

    std::map<uint32_t, libNetwork::TCPv4packet*>::iterator iter1 = snBuffer[bufferNumber].find ( sn );
    std::map<uint32_t, libNetwork::TCPv4packet*>::iterator iter2 = ackExpBuffer[bufferNumber].find ( sn );

    if ( iter1 != snBuffer[bufferNumber].end() ) {
        snBuffer[bufferNumber].erase ( iter1 );
    }

    if ( iter2 != ackExpBuffer[bufferNumber].end() ) {
        ackExpBuffer[bufferNumber].erase ( iter2 );
    }

}


void libNetwork::stream::flushBuffer ( int number ) {

    while ( true ) {

        std::map<uint32_t, libNetwork::TCPv4packet*>::iterator iter = snBuffer[number].find ( snPointer[number] );

        std::cout << "ENTER for buffer " << number << std::endl;

        std::cout << "SEARCH SN  " << snPointer[number] << std::endl;

        if ( iter == snBuffer[number].end() ) {
            break;
        }

        std::cout << "FOUND PACKET" << std::endl;

        charStream[number] += ( *iter ).second->getPayLoad();
        snPointer[number] = ( *iter ).second->getExpectedAcknowledgmentNumber(); // Next SN
        delPacket ( ( *iter ).first, number );

    }

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
    stdstring << charStream[0] << "!" << charStream[1];
    return stdstring.str();;
}

uint64_t libNetwork::stream::getFirstBufferLength() {

    uint64_t bufferlenght = 0;

    for ( std::map<uint32_t, libNetwork::TCPv4packet*>::iterator it = snBuffer[0].begin(); it != snBuffer[0].end(); it++ ) {

        bufferlenght += ( *it ).second->getPayloadLength();

    }


    return bufferlenght;
}

uint64_t libNetwork::stream::getSecondBufferLength() {

    uint64_t bufferlenght = 0;

    for ( std::map<uint32_t, libNetwork::TCPv4packet*>::iterator it = snBuffer[1].begin(); it != snBuffer[1].end(); it++ ) {

        bufferlenght += ( *it ).second->getPayloadLength();

    }

}

uint64_t libNetwork::stream::getFlowLength() {
    return ( charStream[0].length() + charStream[1].length() ) /2;
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
    return snPointer[0];
}

uint32_t libNetwork::stream::getSecondSN() {
    return snPointer[1];
}

bool libNetwork::stream::firstFIN() {
    return fluxFIN[0];
}

bool libNetwork::stream::secondFIN() {
    return fluxFIN[1];
}

std::string libNetwork::stream::getFirstCharStream() {
    return charStream[0];
}

std::string libNetwork::stream::getSecondCharStream() {
    return charStream[1];
}
