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

#ifndef LIBCIGARETTE_H
#define LIBCIGARETTE_H

#include <string>
#include "libPacket.h"

std::string ether_type_decode(int start);
std::string ipv4_type_decode(int start);

#endif //LIBCIGARETTE_H
