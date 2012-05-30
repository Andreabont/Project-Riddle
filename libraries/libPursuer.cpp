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

#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <list>
#include <ios>
#include <boost/asio.hpp>
#include <list>
#include "../commons/libPacket.h"
#include "../commons/libAddress.h"
#include "libPursuer.h"

std::string decodeHexText(std::string raw)
{

    std::string text;

    for(int i = 0; i <= raw.size(); i += 2)
    {
        std::string comp;
        comp += (char)raw[i];
        comp += (char)raw[i+1];
        std::stringstream convert(comp);
        int temp;
        convert >> std::hex >> temp;
        text += (char)temp;
    }

    return text;

}

bool stream::factory(TCPv4packet *packet)
{

    if(packet->isSYN())
    {

        if(!packet->isACK())
        {

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

        }
        else
        {

            if(sequenceNumber[0] + 1 == packet->getAcknowledgmentNumber())
            {
                sequenceNumber[1] = packet->getSequenceNumber();
                delete packet;
                return true;
            }

        }

    }

    delete packet;
    return false;

}


bool stream::addPacket(TCPv4packet *newPacket)
{

    using namespace std;

    int a,b;

    if(!newPacket->isSYN())
    {

        if(newPacket->getSenderPort() == port[0])
        {

            // Siamo nel primo buffer

            a = 1;
            b = 0;

        }
        else if(newPacket->getSenderPort() == port[1])
        {
            // Siamo nel secondo buffer

            a = 0;
            b = 1;

        }
        else return false; // Buffer non identificato.


        if(newPacket->isACK()) // Se c'� ACK setto il flag sul pacchetto corrispondente, se c'�.
        {

            for (list<TCPv4packet*>::iterator it = buffer[a].begin(); it != buffer[a].end(); it++)
            {

                if( (*it)->getSequenceNumber() == newPacket->getAcknowledgmentNumber() - ((*it)->getPayLoad().size()/2))
                {
                    (*it)->public_flag = true;
                    break;
                }
            }

        }

        if(newPacket->getPayLoad().size() != 0) // Salvo il pacchetto solo se ha del payload.
        {
            buffer[b].push_back(newPacket);
        }

        return true;
    }

    return false;

}

void stream::flushBuffer(int number)
{
    bool isFound;

    do {

        isFound = false;

        for (std::list<TCPv4packet*>::iterator it = buffer[number].begin(); it != buffer[number].end(); it++)
        {
            if(sequenceNumber[number] + 1 == (*it)->getSequenceNumber() && (*it)->public_flag)
            {
                std::string payload = (*it)->getPayLoad();
                flow[number] += payload;
                sequenceNumber[number] += payload.size()/2; // unsigned, si azzera come avviene nel tcp.
                buffer[number].remove(*it);
                isFound = true;
                break;
            }
        }

    } while (isFound);

}

void stream::flushFirstBuffer()
{
    flushBuffer(0);
}

void stream::flushSecondBuffer()
{
    flushBuffer(1);
}


std::string stream::exportFlow()
{
    std::stringstream stdstring;
    stdstring << timeEpoch << "!" << timeMillis << "!";
    stdstring << macAddress[0].to_string() << "!" << macAddress[1].to_string() << "!";
    stdstring << ipAddress[0].to_string() << "!" << ipAddress[1].to_string() << "!";
    stdstring << port[0] << "!" << port[1] << "!";
    stdstring << flow[0] << "!" << flow[1];
    return stdstring.str();;
}

std::string stream::exportRawFlow()
{
    std::stringstream stdstring;
    stdstring << ">> Nuovo flusso:" << std::endl;
    stdstring << ">> A -> B:" << std::endl;
    stdstring << decodeHexText(flow[0]) << std::endl;
    stdstring << ">> B -> A:" << std::endl;
    stdstring << decodeHexText(flow[1]) << std::endl;
    return stdstring.str();
}

uint64_t stream::getBufferLength()
{

    uint64_t bufferlenght = 0;

    for(int i = 0; i <= 1; i++)
    {

        for (std::list<TCPv4packet*>::iterator it = buffer[i].begin(); it != buffer[i].end(); it++)
        {

            bufferlenght += (*it)->getPayloadLength();

        }

    }

    return bufferlenght;
}

uint64_t stream::getFlowLength()
{
    return (flow[0].length() + flow[1].length())/2;
}

uint64_t stream::getTimeEpoch()
{
    return timeEpoch;
}

uint32_t stream::getTimeMillis()
{
    return timeMillis;
}

mac_address stream::getFirstMacAddress()
{
    return macAddress[0];
}

mac_address stream::getSecondMacAddress()
{
    return macAddress[1];
}

boost::asio::ip::address stream::getFirstIpAddress()
{
    return ipAddress[0];
}

boost::asio::ip::address stream::getSecondIpAddress()
{
    return ipAddress[1];
}

uint16_t stream::getFirstPort()
{
    return port[0];
}

uint16_t stream::getSecondPort()
{
    return port[1];
}

uint32_t stream::getFirstSN()
{
    return sequenceNumber[0];
}

uint32_t stream::getSecondSN()
{
    return sequenceNumber[1];
}

bool stream::isFIN()
{
    return flagFirstFIN && flagSecondFIN;
}