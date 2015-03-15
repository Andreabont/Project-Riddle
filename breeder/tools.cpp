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
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>

#include "tools.h"

void breederConfig::init()
{

    boost::property_tree::ptree root;

    boost::property_tree::ptree global;
    global.put( "threshold", "90" );
    global.put( "protocols", "http ftp" );

    root.push_front(
        boost::property_tree::ptree::value_type( "global", global )
    );

    boost::property_tree::ptree http;
    http.put( "description", "The Hypertext Transfer Protocol (HTTP) is an application protocol for distributed hypermedia information systems." );
    http.put( "regexp_content", "HTTP/[0-9]\\.[0-9]" );
    http.put( "regexp_score", "80" );
    http.put( "ports_content", "80 8080" );
    http.put( "ports_score", "20" );

    boost::property_tree::ptree ftp;
    ftp.put( "description", "File Transfer Protocol (FTP) is a standard network protocol used to transfer files from one host to another host over a TCP-based network." );
    ftp.put( "regexp_content", "USER#.*?#.*?PASS" );
    ftp.put( "regexp_score", "20" );
    ftp.put( "ports_content", "21" );
    ftp.put( "ports_score", "80" );

    // TODO Aggiungi protocolli.

    root.push_back(
        boost::property_tree::ptree::value_type( "http", http )
    );

    root.push_back(
        boost::property_tree::ptree::value_type( "ftp", ftp )
    );

    boost::property_tree::ini_parser::write_ini( BREEDERCONFIG, root );

}

boost::property_tree::ptree breederConfig::load()
{

    boost::property_tree::ptree config;
    boost::property_tree::ini_parser::read_ini( BREEDERCONFIG, config );

    return config;

}

bool breederConfig::fexists()
{

    std::ifstream ifile( BREEDERCONFIG );
    return ifile;

}

std::vector< std::string > breederConfig::getProtocolsAvailable(boost::property_tree::ptree config)
{
    std::vector< std::string > pavailable;
    std::string temp = config.get< std::string >("global.protocols");
    boost::algorithm::split ( pavailable, temp, boost::algorithm::is_any_of ( " " ) );
    return pavailable;
}

std::vector< int > breederConfig::getPortsAvailable(boost::property_tree::ptree config, std::string filter)
{
    std::string temp = config.get< std::string >(filter+".ports_content");
    std::vector< std::string > sports;
    boost::algorithm::split ( sports, temp, boost::algorithm::is_any_of ( " " ) );
    std::vector< int > ports( sports.size() );

    for (unsigned int i = 0; i < sports.size(); i++) {
        ports[i] = boost::lexical_cast<int> ( sports[i] );
    }

    return ports;

}

std::list< std::string > breederTools::protocolsValidation(std::vector< std::string > select, std::vector< std::string > available)
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

bool breederTools::portsValidation(int select, std::vector< int > available)
{

    for (std::vector< int >::iterator it = available.begin(); it != available.end(); ++it) {

        if(*it == select) {

            return true;

        }

    }

    return false;

}
