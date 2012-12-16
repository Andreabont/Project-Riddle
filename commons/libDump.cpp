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

#define LINE 16

#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <stdint.h>
#include <string.h>
#include "libDump.h"


std::string libDump::classicDump ( std::string input, uint64_t timeEpoch, uint32_t timeMillis ) {

    std::stringstream out;

    out << "[ epoch: " << timeEpoch << " ] -> " << timeMillis << "ms" << std::endl;
    out << classicDump ( input );

    return out.str();

}

std::string libDump::classicDump ( std::string input ) {

    std::stringstream out;
    int stringlen = input.length();
    int stringtodo = input.length();

    for ( uint16_t address = 0; address < stringlen; address += LINE*2 ) {
        out << "0x" << std::setfill ( '0' ) << std::setw ( 5 ) << std::hex << address/2 << " | ";

        for ( int i = 0; i < LINE*2; i+=2 ) {

            if ( i < stringtodo ) {

                out << std::hex << input[address + i];
                out << std::hex << input [address + i + 1] << " ";

            } else {

                out << "   ";

            }

            if ( i == LINE-2 ) {
                out << " ";
            }

        }

        out << "| ";

        for ( int i = 0; i < LINE*2; i+=2 ) {

            if ( i < stringtodo ) {

                std::string comp;
                comp += ( char ) input[address + i];
                comp += ( char ) input[address + i + 1];
                std::stringstream convert ( comp );
                int temp;
                convert >> std::hex >> temp;
                if ( ( temp >= 32 ) && ( temp <= 126 ) ) {
                    out << ( char ) temp;
                } else {
                    out << ".";
                }

            } else {

                out << "   ";

            }

            if ( i == LINE-2 ) {
                out << " ";
            }



        }

        out << std::endl;

        stringtodo = stringtodo - LINE*2;

    }

    return out.str();
}