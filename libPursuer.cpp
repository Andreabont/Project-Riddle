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
    return;
}

long int stream::getTimeEpoch()
{

}

int stream::getTimeMillis()
{

}

mac_address stream::getFirstMacAddress()
{

}

mac_address stream::getSecondMacAddress()
{

}

boost::asio::ip::address stream::getFirstIpAddress()
{

}

boost::asio::ip::address stream::getSecondIpAddress()
{

}

unsigned int stream::getFirstPort()
{

}

unsigned int stream::getSecondPort()
{

}
