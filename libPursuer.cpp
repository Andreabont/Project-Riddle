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
#include <ios>
#include <boost/asio.hpp>
#include "libPacket.h"
#include "libAddress.h"
#include "libPursuer.h"

stream::stream(long int timeEpoch_i, int timeMillis_i)
{
    timeEpoch = timeEpoch_i;
    timeMillis = timeMillis_i;
    first_port = 0;
    second_port = 0;
    flagFull = false;
    return;
}

bool stream::addPacket(TCPv4packet *newPacket)
{

    if(first_port == 0 && second_port == 0)
    {
        // First time

        first_mac = newPacket->getSenderMac();
        second_mac = newPacket->getTargetMac();

        first_ip = newPacket->getSenderIp();
        second_ip = newPacket->getTargetIp();

        first_port = newPacket->getSenderPort();
        second_port = newPacket->getTargetPort();

        first_flow += newPacket->getPayLoad();

        if(newPacket->isFIN() || newPacket->isRST()) {
            flagFull = true;
        }

        return true;

    }
    if(first_port == newPacket->getSenderPort() && first_ip == newPacket->getSenderIp() && first_mac == newPacket->getSenderMac())
    {

        first_flow += newPacket->getPayLoad();

        if(newPacket->isFIN() || newPacket->isRST()) {
            flagFull = true;
        }

    }
    if(second_port == newPacket->getSenderPort() && second_ip == newPacket->getSenderIp() && second_mac == newPacket->getSenderMac())
    {

        second_flow += newPacket->getPayLoad();

        if(newPacket->isFIN() || newPacket->isRST()) {
            flagFull = true;
        }

    } else {
        return false;
    }
}

long int stream::getTimeEpoch()
{
    return timeEpoch;
}

int stream::getTimeMillis()
{
    return timeMillis;
}

mac_address stream::getFirstMacAddress()
{
    return first_mac;
}

mac_address stream::getSecondMacAddress()
{
    return second_mac;
}

boost::asio::ip::address stream::getFirstIpAddress()
{
    return first_ip;
}

boost::asio::ip::address stream::getSecondIpAddress()
{
    return second_ip;
}

unsigned int stream::getFirstPort()
{
    return first_port;
}

unsigned int stream::getSecondPort()
{
    return second_port;
}

bool stream::isFull()
{
    return flagFull;
}
