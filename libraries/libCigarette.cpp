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
 *  Foobar is free software: you can redistribute it and/or modify
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

#include <cstdio>
#include <cstdlib>
#include <stdio.h>
#include <string>
#include "libCigarette.h"

std::string ether_type_decode(uint16_t  start)
{
    // Maggiore o uguale di 1536(0x0600) per Ethernet v2, minore per versione

    if (start >= ETHER_V2_CODE)
    {
        switch (start)
        {
        case (ETHER_TYPE_IPV4):
            return "IPv4";
        case (ETHER_TYPE_ARP):
            return "ARP";
        case (ETHER_TYPE_IPV6):
            return "IPv6";
        case (ETHER_TYPE_PPP):
            return "PPP";
        case (ETHER_TYPE_IEEE802):
            return "IEEE 802.1Q";
        default:
            return "UNDEFINED";
        }
    }
    else return "Ethernet IEEE 802.3";
}

std::string ipv4_type_decode(uint16_t  start)
{
    switch (start)
    {
    case (IPV4_TYPE_TCP):
        return "TCP";
    case (IPV4_TYPE_UDP):
        return "UDP";
    case (IPV4_TYPE_ICMP):
        return "ICMP";
    default:
        return "UNDEFINED";
    }
}

std::string icmpv4_type_decode(uint16_t  start)
{
    switch (start)
    {
    case (ICMPV4_ECHO_REQ):
        return "ECHO Request";
    case (ICMPV4_ECHO_REP):
        return "ECHO Reply";
    default:
        return "UNDEFINED";
    }
}

