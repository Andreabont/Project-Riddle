/**
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 *
 * Name        :  Project Riddle
 * Author      :  Andrea Bontempi
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
#include "tcpflow.h"
#include "macaddress.h"
#include "packet.h"

bool network::TcpStream::factory ( std::shared_ptr<network::TCPv4packet> packet ) {

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

            return true;

        } else {

            if ( snPointer[0] + 1 == packet->getAcknowledgmentNumber() ) {
                snPointer[0]++;
                snPointer[1] = packet->getSequenceNumber() + 1;
                return true;
            }

        }

    }

    return false;

}

void network::TcpStream::factory ( std::string newflow ) {

    std::vector< std::string > section;
    boost::algorithm::split ( section, newflow, boost::algorithm::is_any_of ( "!" ) );

    timeEpoch = boost::lexical_cast<uint64_t> ( section[0] );
    timeMillis = boost::lexical_cast<uint64_t> ( section[1] );
    macAddress[0].from_string( section[2] );
    macAddress[1].from_string( section[3] );
    ipAddress[0] = boost::asio::ip::address::from_string( section[4] );
    ipAddress[1] = boost::asio::ip::address::from_string( section[5] );
    port[0] =  boost::lexical_cast<uint16_t> ( section[6] );
    port[1] =  boost::lexical_cast<uint16_t> ( section[7] );
    charStream[0] = section[8];
    charStream[1] = section[9];

}

bool network::TcpStream::addPacket ( std::shared_ptr<network::TCPv4packet> newPacket ) {

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


        if ( newPacket->isACK() ) { // Se c'e' ACK setto il flag sul pacchetto corrispondente, se c'e'.


            std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator iter = ackExpBuffer[a].find ( newPacket->getAcknowledgmentNumber() );

            if ( iter != ackExpBuffer[a].end() ) {

                ( *iter ).second->public_flag == true;

                uint32_t ackExpToFind = ( *iter ).second->getSequenceNumber();

                bool endLoop = false;

                while ( !endLoop ) {

                    std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator subIter = ackExpBuffer[a].find ( ackExpToFind );

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

            // Sovrascrivo se ritrasmissione.

            std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator searchIter1 = snBuffer[b].find ( newPacket->getSequenceNumber() );
            std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator searchIter2 = ackExpBuffer[b].find ( newPacket->getExpectedAcknowledgmentNumber() );

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

void network::TcpStream::delPacket ( uint32_t sn, int bufferNumber ) {

    std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator iter1 = snBuffer[bufferNumber].find ( sn );
    std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator iter2 = ackExpBuffer[bufferNumber].find ( sn );

    if ( iter1 != snBuffer[bufferNumber].end() ) {
        snBuffer[bufferNumber].erase ( iter1 );
    }

    if ( iter2 != ackExpBuffer[bufferNumber].end() ) {
        ackExpBuffer[bufferNumber].erase ( iter2 );
    }

}


void network::TcpStream::flushBuffer ( int number ) {

    while ( true ) {

        std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator iter = snBuffer[number].find ( snPointer[number] );

        if ( iter == snBuffer[number].end() ) {
            break;
        }

        charStream[number] += ( *iter ).second->getPayLoad();
        snPointer[number] = ( *iter ).second->getExpectedAcknowledgmentNumber(); // Next SN
        delPacket ( ( *iter ).first, number );

    }

}

void network::TcpStream::flushFirstBuffer() {
    flushBuffer ( 0 );
}

void network::TcpStream::flushSecondBuffer() {
    flushBuffer ( 1 );
}


std::string network::TcpStream::exportFlow() {
    std::stringstream stdstring;
    stdstring << timeEpoch << "!" << timeMillis << "!";
    stdstring << macAddress[0].to_string() << "!" << macAddress[1].to_string() << "!";
    stdstring << ipAddress[0].to_string() << "!" << ipAddress[1].to_string() << "!";
    stdstring << port[0] << "!" << port[1] << "!";
    stdstring << charStream[0] << "!" << charStream[1];
    return stdstring.str();;
}

uint64_t network::TcpStream::getFirstBufferLength() {

    uint64_t bufferlenght = 0;

    for ( std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator it = snBuffer[0].begin(); it != snBuffer[0].end(); it++ ) {

        bufferlenght += ( *it ).second->getPayloadLength();

    }


    return bufferlenght;
}

uint64_t network::TcpStream::getSecondBufferLength() {

    uint64_t bufferlenght = 0;

    for ( std::map<uint32_t, std::shared_ptr<network::TCPv4packet>>::iterator it = snBuffer[1].begin(); it != snBuffer[1].end(); it++ ) {

        bufferlenght += ( *it ).second->getPayloadLength();

    }

}

uint64_t network::TcpStream::getFlowLength() {
    return ( charStream[0].length() + charStream[1].length() ) /2;
}

uint64_t network::TcpStream::getTimeEpoch() {
    return timeEpoch;
}

uint32_t network::TcpStream::getTimeMillis() {
    return timeMillis;
}

network::mac_address network::TcpStream::getFirstMacAddress() {
    return macAddress[0];
}

network::mac_address network::TcpStream::getSecondMacAddress() {
    return macAddress[1];
}

boost::asio::ip::address network::TcpStream::getFirstIpAddress() {
    return ipAddress[0];
}

boost::asio::ip::address network::TcpStream::getSecondIpAddress() {
    return ipAddress[1];
}

uint16_t network::TcpStream::getFirstPort() {
    return port[0];
}

uint16_t network::TcpStream::getSecondPort() {
    return port[1];
}

uint32_t network::TcpStream::getFirstSN() {
    return snPointer[0];
}

uint32_t network::TcpStream::getSecondSN() {
    return snPointer[1];
}

bool network::TcpStream::firstFIN() {
    return fluxFIN[0];
}

bool network::TcpStream::secondFIN() {
    return fluxFIN[1];
}

std::string network::TcpStream::getFirstCharStream() {
    return charStream[0];
}

std::string network::TcpStream::getSecondCharStream() {
    return charStream[1];
}
