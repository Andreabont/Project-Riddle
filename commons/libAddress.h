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

#ifndef LIBADDRESS_H
#define LIBADDRESS_H

#include <string>
#include <cstring>
#include <stdint.h>

/* Class for managing MAC address */
class mac_address
{
  
private:
    uint16_t byte[6];

public:

    /** Costruttore: riceve indirizzo in stringa codifica esadecimale. */
    mac_address() {
        std::memset(byte,0,6);
    }
    mac_address(const std::string&);

    bool operator==(const mac_address& otherMac);

    /** Restituisce stringa stampabile a schermo. */
    std::string to_string();
};

#endif //LIBADDRESS_H
