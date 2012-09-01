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

#ifndef LIBBREEDER_H
#define LIBBREEDER_H

#define FILECONFIG "/tmp/breeder.conf"

#include <string>
#include <list>
#include <vector>
#include <boost/property_tree/ptree.hpp>

namespace breederConfig {

void init();
boost::property_tree::ptree load();
bool fexists();

std::vector< std::string > getProtocolsAvailable(boost::property_tree::ptree config);
std::vector< int > getPortsAvailable(boost::property_tree::ptree config, std::string filter);

}

namespace breederTools {

std::list<std::string> protocolsValidation(std::vector<std::string> select, std::vector<std::string> available);
bool portsValidation(int select, std::vector< int > available);

}

#endif //LIBBREEDER_H
