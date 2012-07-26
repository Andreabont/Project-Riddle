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
#include <cstdio>
#include <cstdlib>
#include <string>
#include <limits>
#include <pcap.h>
#include <boost/program_options.hpp>
#include "./libraries/libRiddle.h"

#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#endif

using namespace std;
using namespace boost::program_options;

int main ( int argc, char **argv ) {
    options_description desc ( "Riddle - Network Sniffer" );
    desc.add_options()
    ( "help,h", "prints this" )
    ( "dump,d", "enable dump mode" )
    ( "iface,i", value<string>(), "interface to sniff from (not set = default device)" )
    ( "input,I", value<string>(), "reads packets from a pcap file (disable iface input)" )
    ( "filter,f", value<string>(), "use to filter packet with bpf" )
    ( "limit,l", value<int>(), "set max number of packet" )
#ifdef __linux__
    ( "secure,s", "Drop root privileges after initialization." )
#endif
    ;

    variables_map vm;

    try {
        store ( parse_command_line ( argc, argv, desc ), vm );
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
        cout << desc << endl;
        return EXIT_SUCCESS;
    }

#ifdef __linux__
    int realuid, realgid, effectiveuid, effectivegid;
    if ( vm.count ( "secure" ) ) {

        realuid = getuid();		// UID del lanciatore
        effectiveuid = geteuid();	// UID del proprietario
        realgid = getgid();		// GID del lanciatore
        effectivegid = getegid();	// GID del proprietario

        if ( realuid == -1 || effectiveuid == -1 || realgid == -1 || effectivegid == -1 ) {
            cerr << "ERROR >> Can't read real and effective UID/GID." << endl;
            return EXIT_FAILURE;
        }

        if ( effectiveuid || effectivegid ) {
            cerr << "ERROR >> To use the \"secure\" option the program must be owned by root and must have enabled the setuid bit. (EUID = " << effectiveuid << ", EGID = " << effectivegid << ")" << endl;
            return EXIT_FAILURE;
        }

        if ( !realuid || !realgid ) {
            cerr << "ERROR >> To use the \"secure\" option the program must't run as root. (RUID = " << realuid << ", RGID = " << realgid << ")" << endl;
            return EXIT_FAILURE;
        }

    }
#endif

    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *pcap_handle;

    if ( vm.count ( "input" ) ) {
        pcap_handle = pcap_open_offline ( vm["input"].as<string>().c_str(), error_buffer );
        if ( pcap_handle == NULL ) {
            pcap_fatal ( "pcap_open_offline", error_buffer );
        }
        cerr << ">> Reading packets from " << vm["input"].as<string>() << endl;
    } else {

        string pcap_device;

        if ( vm.count ( "iface" ) ) {
            pcap_device=vm["iface"].as<string>();
        } else {
            // Cerca e restituisce interfaccia
            char *dev=pcap_lookupdev ( error_buffer );
            if ( dev!=NULL ) pcap_device = dev;
            else pcap_fatal ( "pcap_lookupdev", error_buffer );
        }

        // Apre il device in mod promiscua
        pcap_handle = pcap_open_live ( pcap_device.c_str(), 4096, 1, 0, error_buffer );
        if ( pcap_handle == NULL ) {
            pcap_fatal ( "pcap_open_live", error_buffer );
        }
        cerr << ">> Sniffing on device " << pcap_device << endl;
    }

#ifdef __linux__
    if ( vm.count ( "secure" ) ) {
        cerr << ">> Drop root privileges. Set Real UID to '" << realuid << "' and Real GID to '" << realgid << "'." << endl;
        seteuid ( realuid );
        setegid ( realgid );
    }
#endif

    if ( vm.count ( "filter" ) ) {
        string filter = vm["filter"].as<string>();
        struct bpf_program fp;
        bpf_u_int32 net;

        cerr << ">> Filtering with '" << filter << "'" << endl;

        if ( pcap_compile ( pcap_handle, &fp, filter.c_str(), 0, net ) == -1 ) {
            cerr << "ERROR >> Couldn't parse filter '" << filter << "': "<< pcap_geterr ( pcap_handle ) << endl;
            return ( 2 );
        }

        if ( pcap_setfilter ( pcap_handle, &fp ) == -1 ) {
            cerr << "ERROR >> Couldn't install filter '" << filter << "': "<<pcap_geterr ( pcap_handle ) << endl;
            return ( 2 );
        }
    }

    int maxpacket = numeric_limits<int>::max();

    if ( vm.count ( "limit" ) ) {
        maxpacket=vm["limit"].as<int>();
    }

    void ( *dumper ) ( const unsigned char*,struct pcap_pkthdr );
    if ( vm.count ( "dump" ) ) dumper=hexDump;
    else dumper=rawDump;

    const u_char *packet;
    pcap_pkthdr header;

    for ( ; maxpacket > 0; ) {
        packet = pcap_next ( pcap_handle, &header );
        if ( packet == NULL ) {
            cerr << ">> Flow terminated" << endl;
            break;
        }
        dumper ( packet, header );
        if ( maxpacket!=numeric_limits<int>::max() ) maxpacket--;
    }

    cerr << ">> I finished the job, goodbye!" << endl;
    pcap_close ( pcap_handle );

    return EXIT_SUCCESS;
}
