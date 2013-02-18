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
#include <pcap.h>
#include <boost/program_options.hpp>
#include "./commons/libDump.h"

#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/resource.h>
#define MIN_NICE -15
#endif

using namespace std;
using namespace boost::program_options;

pcap_t *pcap_handle;

string ( *dumper ) ( string, uint64_t, uint32_t );
void ( *process_packet ) ( u_char*, const struct pcap_pkthdr*, const u_char* );

void fast_process_packet ( u_char* useless, const struct pcap_pkthdr* header, const u_char* packet ) {

    cout << dumper ( libDump::encodeHexText ( packet, header->len ), header->ts.tv_sec, header->ts.tv_usec );

}

void precise_process_packet ( u_char* useless, const struct pcap_pkthdr* header, const u_char* packet ) {

    cout << dumper ( libDump::encodeHexText ( packet, header->len ), header->ts.tv_sec, header->ts.tv_usec );
    cout.flush();  // Flushing the standard output will decrease the performance.

}


#ifdef __linux__
void exit_signal ( int id ) {
    cout << ">> Exit signal detected. (" << id << ")" << endl;
    if ( pcap_handle != NULL ) {
        pcap_breakloop ( pcap_handle );
        pcap_close ( pcap_handle );
    }
    exit ( 0 );
}
#endif

int main ( int argc, char **argv ) {

#ifdef __linux__
    signal ( SIGINT, exit_signal );     /* Ctrl-C */
    signal ( SIGQUIT, exit_signal );    /* Ctrl-\ */
#endif

    options_description desc ( "Riddle - Network Sniffer" );
    desc.add_options()
    ( "help,h", "prints this" )
    ( "dump,d", "enable dump mode" )
    ( "iface,i", value< string >(), "interface to sniff from. [auto]" )
    ( "iface-list,y", "prints all available devices." )
    ( "pcap,p", value< string >(), "reads packets from a pcap file (disable iface input)" )
    ( "filter,f", value< vector< string > >()->multitoken(), "use to filter packet with bpf" )
    ( "limit,l", value< int >(), "set max number of packet" )
    ( "snaplen,a", value< int >(), "maximum amount of data to be captured. [1500]" )
    ( "rfmon,m", "enable monitor mode. (disable promiscuous mode)" )
    ( "no-promisc,n", "disable promiscuous mode." )
    ( "rapid,j", "enable mode for fast connections." )
#ifdef __linux__
    ( "secure,s", "drop root privileges after initialization." )
    ( "renice,r", value< int >(), "renice the process. [default 0]" )
#endif
    ;

    variables_map vm;

    try {
        store ( parse_command_line ( argc, argv, desc ), vm );
        notify ( vm );
    } catch ( boost::program_options::unknown_option ex1 ) {
        cerr << "ERROR >> " << ex1.what() << "" << endl;
        cerr << ">> Try '" << argv[0] << " --help' for more information." << endl;
        return EXIT_FAILURE;
    } catch ( boost::program_options::invalid_command_line_syntax ex2 ) {
        cerr << "ERROR >> " << ex2.what() << "" << endl;
        cerr << ">> Try '" << argv[0] << " --help' for more information." << endl;
        return EXIT_FAILURE;
    }

    if ( vm.count ( "help" ) ) {
        cout << desc << endl;
        return EXIT_SUCCESS;
    }

    if ( vm.count ( "iface-list" ) ) {

        pcap_if_t *alldevsp, *device;
        char error_buffer[100];

        cerr << ">> Finding available devices ... " << endl;
        if ( pcap_findalldevs ( &alldevsp , error_buffer ) ) {
            cerr << "ERROR >> pcap_findalldevs: " << error_buffer << endl;
            return EXIT_FAILURE;
        }

        cerr << ">> I found these devices: ";

        for ( device = alldevsp ; device != NULL ; device = device->next ) {
            cerr << device->name << " ";
        }

        cerr << endl;

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

    if ( vm.count ( "pcap" ) ) {

        pcap_handle = pcap_open_offline ( vm["pcap"].as<string>().c_str(), error_buffer );

        if ( pcap_handle == NULL ) {
            cerr << "ERROR >> pcap_open_offline: " << error_buffer << endl;
            return EXIT_FAILURE;
        }

        cerr << ">> Reading packets from " << vm["input"].as<string>() << endl;

    } else {

        string pcap_device;

        if ( vm.count ( "iface" ) ) {
            pcap_device=vm["iface"].as<string>();
        } else {

            // Cerca e restituisce interfaccia
            char *dev=pcap_lookupdev ( error_buffer );
            if ( dev!=NULL ) {
                pcap_device = dev;
            } else {
                cerr << "ERROR >> pcap_lookupdev: " << error_buffer << endl;
                return EXIT_FAILURE;
            }

        }

        pcap_handle = pcap_create ( pcap_device.c_str(), error_buffer );

        if ( pcap_handle == NULL ) {
            cerr << "ERROR >> pcap_create: " << error_buffer << endl;
            return EXIT_FAILURE;
        }

        int status = 0;

        int snaplen = 1500;

        if ( vm.count ( "snaplen" ) ) {
            snaplen=vm["snaplen"].as<int>();
            cerr << ">> Capture maximum " << vm["snaplen"].as<int>() << " bytes." << endl;
        }

        status = pcap_set_snaplen ( pcap_handle, snaplen );

        if ( status != 0 ) {
            return EXIT_FAILURE;
        }

        if ( vm.count ( "rfmon" ) ) {
            status = pcap_set_rfmon ( pcap_handle, 1 );
            if ( status != 0 ) {
                return EXIT_FAILURE;
            }
            cerr << ">> Monitor mode enabled." << endl;
        }

        int promisc = 1;

        if ( vm.count ( "no-promisc" ) || vm.count ( "rfmon" ) ) {
            promisc = 0;
            cerr << ">> Promiscuous mode disabled." << endl;
        }

        status = pcap_set_promisc ( pcap_handle, promisc );

        if ( status != 0 ) {
            return EXIT_FAILURE;
        }

        status = pcap_set_timeout ( pcap_handle, 0 );

        if ( status != 0 ) {
            return EXIT_FAILURE;
        }

        status = pcap_activate ( pcap_handle );

        if ( status != 0 ) {

            switch ( status ) {

            case PCAP_ERROR_PERM_DENIED :
                cerr << "ERROR >> You do not have permission to open the device." << endl;
                break;

            case PCAP_ERROR_IFACE_NOT_UP:
                cerr << "ERROR >> The device \"" << pcap_device.c_str() << "\" isn't up." << endl;
                break;

            case PCAP_ERROR_NO_SUCH_DEVICE:
                cerr << "ERROR >> The device \"" << pcap_device.c_str() << "\" does not exist." << endl;
                cerr << ">> Try '" << argv[0] << " --iface-list' for more information." << endl;
                break;

            case PCAP_ERROR_PROMISC_PERM_DENIED:
                cerr << "ERROR >> You do not have permission to open the device \"" << pcap_device.c_str() << "\" in promiscuous mode." << endl;
                break;

            case PCAP_ERROR_RFMON_NOTSUP :
                cerr << "ERROR >> The device \"" << pcap_device.c_str() << "\" doesn't support monitor mode." << endl;
                break;

            default:
                cerr << "ERROR >> ID: " << status << "" << endl;
            }

            return EXIT_FAILURE;
        }

        cerr << ">> Sniffing on device: " << pcap_device << endl;
    }

#ifdef __linux__
    if ( vm.count ( "renice" ) ) {
        int id;
        int prior = vm["renice"].as<int>();
        if ( prior < MIN_NICE ) {
            prior = MIN_NICE;
            cerr << ">> The limit for renice is " << MIN_NICE << "." << endl;
        }
        cerr << ">> Renice process to " << prior << "." << endl;
        id = setpriority ( PRIO_PROCESS, getpid(), prior );
    }

    if ( vm.count ( "secure" ) ) {
        cerr << ">> Drop root privileges. Set Real UID to '" << realuid << "' and Real GID to '" << realgid << "'." << endl;
        seteuid ( realuid );
        setegid ( realgid );
    }
#endif

    if ( vm.count ( "filter" ) ) {
        vector < string > filterraw = vm["filter"].as< vector < string > >();

        string filter;

        for ( int i = 0; i < filterraw.size(); i++ ) {
            filter.append ( filterraw[i] );
            if ( i != filterraw.size() - 1 ) filter.append ( " " );
        }

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

    int maxpacket = -1;

    if ( vm.count ( "limit" ) ) {
        maxpacket=vm["limit"].as<int>();
    }

    if ( vm.count ( "dump" ) ) {
        dumper = libDump::classicDump;
    } else {
        dumper = libDump::riddleDump;
    }

    if ( vm.count ( "rapid" ) ) {
        process_packet = fast_process_packet;
        cerr << ">> Rapid mode enabled." << endl;
    } else {
        process_packet = precise_process_packet;
    }

    pcap_loop ( pcap_handle , maxpacket , process_packet , NULL );

    // TODO Gesisci segnale di terminazione e usa pcap_breakloop.

    cerr << ">> I finished the job, goodbye!" << endl;

    pcap_close ( pcap_handle );

    return EXIT_SUCCESS;
}
