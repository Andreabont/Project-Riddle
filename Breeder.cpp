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

#include <iostream>
#include <string>
#include <vector>
#include <boost/regex.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/program_options.hpp>
#include "./libraries/libBreeder.h"
#include "./commons/classPacket.h"
#include "./commons/classFlow.h"
#include "./commons/libDump.h"

using namespace std;
using namespace boost::program_options;
using namespace libNetwork;

int main ( int argc, char **argv ) {
    options_description desc ( "Breeder - Network TCP Flux Seletor" );
    desc.add_options()
    ( "help,h", "prints this" )
    ( "filters,f", value< vector<string> >(), "specifies a list of protocols." )
    ;

    positional_options_description p;
    p.add("filters", -1);

    variables_map vm;

    try {
        store(command_line_parser(argc, argv).
              options(desc).positional(p).run(), vm);
        notify ( vm );
    } catch ( boost::program_options::unknown_option ex1 ) {
        cerr << "ERROR >> " << ex1.what() << "" << endl;
        cerr << ">> Try '" << argv[0] << " --help' for more information." << endl;
        return EXIT_SUCCESS;
    } catch ( boost::program_options::invalid_command_line_syntax ex2 ) {
        cerr << "ERROR >> " << ex2.what() << "" << endl;
        cerr << ">> Try '" << argv[0] << " --help' for more information." << endl;
        return EXIT_SUCCESS;
    }

    if ( vm.count ( "help" ) ) {
        cout<<desc<<"\n";
        return EXIT_SUCCESS;
    }

    if ( !vm.count ( "filters" ) || vm["filters"].as< vector<string> >().empty() ) {
        std::cerr<<"ERROR >> You have not selected any protocol!"<<std::endl;
        return EXIT_FAILURE;
    }

    if( !breederConfig::fexists() ) {
        breederConfig::init();
    }

    boost::property_tree::ptree config = breederConfig::load();

    vector< string > pselect = vm["filters"].as< vector< string > >();
    vector< string > pavailable;
    string temp = config.get< std::string >("global.protocols");
    boost::algorithm::split ( pavailable, temp, boost::algorithm::is_any_of ( " " ) );

    list< string > filters = breederConfig::protocolsValidation( pselect, pavailable );

    if ( filters.empty() ) {
        std::cerr<<"ERROR >> You have not selected any protocol!"<<std::endl;
        return EXIT_FAILURE;
    }

    // TODO

    list<std::string> regularexpressions;

    if ( vm.count ( "http" ) ) {
        regularexpressions.push_front ( ".*HTTP.*" );
    }


    while ( 1 ) {
        try {
            string r_flux, a_flux, b_flux;
            getline ( cin,r_flux );
            if ( cin.eof() ) break;

            stream * flow = new stream();
            flow->factory ( r_flux );

            a_flux = libDump::decodeHexText ( flow->getFirstCharStream() );
            b_flux = libDump::decodeHexText ( flow->getSecondCharStream() );

            boost::regex regexp ( ".*HTTP.*" ); // TODO

            if ( boost::regex_match ( a_flux, regexp ) || boost::regex_match ( b_flux, regexp ) ) {
                cout << flow->exportFlow() << endl;
            }

            delete flow;

        } catch ( packet::Overflow ) {
            std::cerr<<"Overflow! :-P"<<std::endl;
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
