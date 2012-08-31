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

#include <string>
#include <list>
#include <vector>
#include <fstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include "libBreeder.h"

void breederConfig::init()
{

    boost::property_tree::ptree root;

    boost::property_tree::ptree global;
    global.put( "threshold", "90" );
    global.put( "protocols", "http" );

    root.push_front(
        boost::property_tree::ptree::value_type( "global", global )
    );

    boost::property_tree::ptree http;
    http.put( "description", "..." );
    http.put( "regexp", "HTTP/[0-9]\\.[0-9]" );
    http.put( "ports", "80 8080" );

    root.push_back(
        boost::property_tree::ptree::value_type( "http", http )
    );

    boost::property_tree::ini_parser::write_ini( FILECONFIG, root );

}

boost::property_tree::ptree breederConfig::load()
{

    boost::property_tree::ptree config;
    boost::property_tree::ini_parser::read_ini( FILECONFIG, config );

    return config;

}

bool breederConfig::fexists()
{

    std::ifstream ifile( FILECONFIG );
    return ifile;

}

std::list< std::string > breederConfig::protocolsValidation(std::vector< std::string > select, std::vector< std::string > available)
{

    std::list< std::string > out;

    for (std::vector< std::string >::iterator it = select.begin(); it != select.end(); ++it) {

        for (std::vector< std::string >::iterator it2 = available.begin(); it2 != available.end(); ++it2) {

            if( (*it).compare(*it2) == 0 ) {
                out.push_back(*it);
                break;
            }

        }

    }

    return out;

}

