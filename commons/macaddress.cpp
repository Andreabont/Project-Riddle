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

#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "macaddress.h"

/** Costruttore */
network::mac_address::mac_address( std::string rawData )
{
    this->from_string(rawData);
    return;
}

/** Inizializzatore da stringa (con o senza ':') */
void network::mac_address::from_string ( std::string rawData ) {

    if( rawData.find(':') != std::string::npos ) {
        rawData.erase( std::remove( rawData.begin(), rawData.end(), ':' ), rawData.end() );
    }

    int l = 0;
    std::string temp;
    temp.reserve ( 2 );

    for ( int i=0; i<=11; i++ ) {
        temp += rawData[i];
        if ( i%2 != 0 ) {
            std::stringstream convert ( temp );
            int tempInt;
            convert>>std::hex>>tempInt;
            byte[l]=tempInt;
            l++;
            temp = "";
        }
    }

    return;
}

/** Restituisce indirizzo stampabile */
std::string network::mac_address::to_string() {
    std::string stamp;
    std::stringstream temp;

    for ( int i=0; i<=5; i++ ) {
        temp<<std::setfill ( '0' ) <<std::setw ( 2 ) <<std::hex<< ( int ) byte[i];
        stamp += temp.str();
        temp.str ( "" );
        if ( i != 5 ) stamp += ':';
    }

    return stamp;
}
