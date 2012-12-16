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
#include <iomanip>
#include <string>
#include <sstream>
#include <stdint.h>

namespace libDump {

    /** print hex string in a format style "memory dump". */
    std::string classicDump ( std::string input, uint64_t timeEpoch, uint32_t timeMillis );

    /** print hex string in a format style "memory dump". overload */
    std::string classicDump ( std::string input );

    /** print data in riddle protocol */
    inline std::string riddleDump ( std::string input, uint64_t timeEpoch, uint32_t timeMillis ) {

        std::stringstream out;

        out << timeEpoch << "!" << timeMillis << "!" << input << std::endl;

        return out.str();

    }

    /** decode hex string using the ASCII table. */
    inline std::string decodeHexText ( std::string raw ) {

        std::string text;

        for ( int i = 0; i <= raw.size(); i += 2 ) {
            std::string comp;
            comp += ( char ) raw[i];
            comp += ( char ) raw[i+1];
            std::stringstream convert ( comp );
            int temp;
            convert >> std::hex >> temp;
            text += ( char ) temp;
        }

        return text;

    }

    /** enccoding to hex format */
    inline std::string encodeHexText ( const unsigned char *text, uint32_t size ) {

        std::stringstream out;

        for ( int i = 0; i < size; i++ ) {

            out << std::setfill ( '0' ) << std::setw ( 2 ) << std::hex << ( int ) text[i];

        }

        return out.str();

    }

}

#endif //LIBDUMP_H
