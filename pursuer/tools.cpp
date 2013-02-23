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
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <fstream>
#include <string>
#include <vector>
#include <ios>
#include "commons/packet.h"
#include "commons/macaddress.h"
#include "commons/tcpflow.h"
#include "commons/dumptools.h"
#include "tools.h"

void writeout ( network::TcpStream* stream, bool tofile ) {
    if ( tofile ) {
        std::stringstream filename;
        char buffer[10];
        filename << "flow_";
        filename << stream->getTimeEpoch();
        filename << "_";
        filename << stream->getTimeMillis();
        filename << ".txt";
        std::ofstream myfile;
        myfile.open ( filename.str().c_str() );
        if ( myfile.is_open(), std::ios::out | std::ios::app ) {
            myfile << exportFormattedRawFlow ( stream );
            myfile.close();
        }
    } else {
        std::cout << stream->exportFlow() << std::endl;
    }
}

std::string exportFormattedRawFlow ( network::TcpStream* stream ) {

    uint16_t first_port = stream->getFirstPort();
    uint16_t second_port = stream->getSecondPort();

    std::stringstream stdstring;
    stdstring << ">> Two-way flow between " << stream->getFirstIpAddress().to_string() << ":" << first_port << " and " << stream->getSecondIpAddress().to_string() << ":" << second_port << std::endl;
    stdstring << ">> " << stream->getFirstIpAddress().to_string() << ":" << first_port << " -> " << stream->getSecondIpAddress().to_string() << ":" << second_port << std::endl;
    stdstring << dump::decodeHexText ( stream->getFirstCharStream() ) << std::endl;
    stdstring << ">> " << stream->getSecondIpAddress().to_string() << ":" << second_port << " -> " << stream->getFirstIpAddress().to_string() << ":" << first_port << std::endl;
    stdstring << dump::decodeHexText ( stream->getSecondCharStream() ) << std::endl;
    return stdstring.str();
}

bool isStream ( std::list< network::TcpStream* >::iterator iter, network::TCPv4packet *pkg ) {
    return ( ( ( *iter )->getFirstIpAddress() == pkg->getSenderIp() && ( *iter )->getFirstPort() == pkg->getSenderPort() ) &&
             ( ( *iter )->getSecondIpAddress() == pkg->getTargetIp() && ( *iter )->getSecondPort() == pkg->getTargetPort() ) ) ||
           ( ( ( *iter )->getFirstIpAddress() == pkg->getTargetIp() && ( *iter )->getFirstPort() == pkg->getTargetPort() ) &&
             ( ( *iter )->getSecondIpAddress() == pkg->getSenderIp() && ( *iter )->getSecondPort() == pkg->getSenderPort() ) ) ;
}

