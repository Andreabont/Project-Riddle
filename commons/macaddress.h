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

#ifndef MACADDRESS_H
#define MACADDRESS_H

#include <string>
#include <cstring>
#include <stdint.h>

namespace network {

/* Class for managing MAC address */
class mac_address
{

private:
    uint16_t byte[6]; // FIXME Dovrebbe essere un uint8_t

public:

    /** builds the object with null mac address */
    mac_address() {
        std::memset ( byte, 0, 12 );
    }

    /** builds the object from a hexadecimal string (link to factory) */
    mac_address ( std::string );

    /** builds the object from a hexadecimal string */
    void from_string ( std::string );

    /** implements the comparison between mac address */
    bool operator== ( const mac_address& otherMac );

    /** build printable mac address */
    std::string to_string();
};

}

#endif //MACADDRESS_H
