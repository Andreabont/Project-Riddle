/**
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 *
 * Name        :  Project Riddle
 * Author      :  Andrea Bontempi
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
    uint8_t byte[6];

public:

    /**
     * Builds the object with null mac address.
     * \return an instance of "macaddress".
     */
    mac_address() {
        std::memset ( byte, 0, sizeof(byte) );
    }

    /**
     * Builds the object from a hexadecimal string (link to factory)
     * \param rawData is a mac address in hexadecimal notation. (Colons are optional)
     * \return an instance of "macaddress".
     */
    mac_address ( std::string rawData );

    /**
     * Override the object from a hexadecimal string.
     * \param rawData is a mac address in hexadecimal notation. (Colons are optional)
     */
    void from_string ( std::string );

    /**
     * Build printable mac address in hexadecimal notation with colons.
     * \return a string with the mac address in hexadecimal notation.
     */
    std::string to_string();

    /**
     * Override - Implements the comparison between mac address
     * \param otherMac This is the other mac address to be compared with the local one.
     * \return true if the two addresses match.
     */
    bool operator== ( const mac_address& otherMac )
    {
        return memcmp(byte,otherMac.byte,sizeof(byte))==0;
    }

    /**
     * Override - Implements the comparison between mac address (not equal)
     * \param otherMac This is the other mac address to be compared with the local one.
     * \return true if the two addresses match.
     */
    bool operator!= ( const mac_address& otherMac )
    {
        return !operator==(otherMac);
    }

};

}

#endif //MACADDRESS_H
