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

#ifndef LIBRANGING_H
#define LIBRANGING_H

#include <boost/asio.hpp>
#include "../commons/libAddress.h"

class device
{
private:
    mac_address mac;
    boost::asio::ip::address ip;
    long int timeEpoch;
public:
    device(mac_address newMac, boost::asio::ip::address newIp, long int newEpoch);
    mac_address getMacAddress();
    boost::asio::ip::address getIpAddress();
    long int getEpoch();
    void setEpoch(long int newEpoch);
};

#endif //LIBRANGING_H
