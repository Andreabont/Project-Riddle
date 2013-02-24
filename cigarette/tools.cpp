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

#include <cstdio>
#include <cstdlib>
#include <stdio.h>
#include <string>
#include "tools.h"

std::string ether_type_decode(uint16_t start) {
    // Maggiore o uguale di 1536(0x0600) per Ethernet v2, minore per versione

    if (start >= (int) ethertype::V2_CODE) {
        switch (start) {
            case ( (int) ethertype::IPV4):
                return "IPv4";
            case ( (int) ethertype::ARP):
                return "ARP";
            case ( (int) ethertype::IPV6):
                return "IPv6";
            case ( (int) ethertype::PPP):
                return "PPP";
            case ( (int) ethertype::IEEE802):
                return "IEEE 802.1Q";
            default:
                return "UNDEFINED";
        }
    } else return "Ethernet IEEE 802.3";
}

std::string ipv4_type_decode(uint16_t start) {
    switch (start) {
        case ( ipv4type::TCP):
            return "TCP";
        case ( ipv4type::UDP):
            return "UDP";
        case ( ipv4type::ICMP):
            return "ICMP";
        default:
            return "UNDEFINED";
    }
}

std::string icmpv4_type_decode(uint16_t start) {
    switch (start) {
        case ( icmpv4type::ECHO_REQUEST ):
            return "ECHO Request";
        case ( icmpv4type::ECHO_REPLY ):
            return "ECHO Reply";
        default:
            return "UNDEFINED";
    }
}

