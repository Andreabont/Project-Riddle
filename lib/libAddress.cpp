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

#include <string>
#include <sstream>
#include <iomanip>
#include "libAddress.h"

/** Costruttore */
mac_address::mac_address(const std::string& rawData)
{
    int l = 0;
    std::string temp;
    temp.reserve(2);

    for (int i=0; i<=11; i++)
    {
        temp += rawData[i];
        if (i%2 != 0)
        {
            std::stringstream convert(temp);
            convert>>std::hex>>byte[l];
            l++;
            temp = "";
        }
    }

    return;
}

/** Restituisce indirizzo stampabile */
std::string mac_address::to_string()
{
    std::string stamp;
    std::stringstream temp;

    for (int i=0; i<=5; i++)
    {
        temp<<std::setfill('0')<<std::setw(2)<<std::hex<<(int) byte[i];
        stamp += temp.str();
        temp.str("");
        if (i != 5) stamp += ':';
    }

    return stamp;
}

/** Overload, definisco confronto tra indirizzi */
bool mac_address::operator==(const mac_address& otherMac)
{
    for(int i=0; i<=5; i++)
    {
        if(byte[i] != otherMac.byte[i])
        {
            return false;
        }
    }

    return true;
}
