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

#include "libRanging.h"

device::device(mac_address newMac, boost::asio::ip::address newIp, long int newEpoch)
{
    mac = newMac;
    ip = newIp;
    timeEpoch = newEpoch;
    return;
}

boost::asio::ip::address device::getIpAddress()
{
    return ip;
}

mac_address device::getMacAddress()
{
    return mac;
}

long int device::getEpoch()
{
    return timeEpoch;
}

void device::setEpoch(long int newEpoch)
{
    timeEpoch = newEpoch;
    return;
}
