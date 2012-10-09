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

#ifndef LIHDUMP_H
#define LIBDUMP_H

#include <iostream>
#include <string>
#include <sstream>
#include <stdint.h>

namespace libDump {

/** print hex string in a format style "memory dump". */
std::string classicDump ( std::string input, uint64_t timeEpoch, uint32_t timeMillis );

/** print hex string in a format style "memory dump". overload */
std::string classicDump ( std::string input );

/** print data in riddle protocol */
std::string riddleDump ( std::string input, uint64_t timeEpoch, uint32_t timeMillis );

/** decode hex string using the ASCII table. */
std::string decodeHexText ( std::string raw );

/** enccoding to hex format */
std::string encodeHexText ( const unsigned char *text, uint32_t size);

}

#endif //LIBDUMP_H
