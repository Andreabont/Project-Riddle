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
#include <iomanip>
#include <list>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/concept_check.hpp>
#include <boost/thread/thread.hpp>
#include <boost/date_time.hpp>
#include <sys/time.h>

#include <curses.h>
#include "./commons/classMacAddress.h"
#include "./commons/classPacket.h"
#include "./libraries/libRanging.h"

#define TIMETOLIVE 50

int rows; // number of rows in window
int cols; // number of columns in window

using namespace std;
using namespace boost;
using namespace boost::program_options;
using namespace boost::gregorian;
using namespace boost::posix_time;
using namespace libNetwork;

boost::mutex mymutex;

void setHead();
void printLine ( int countLine, string mac, string ip, long int epoch );

void printer ( list<device> *found ) {

    static boost::posix_time::seconds delay ( 1 );

    while ( 1 ) {

        boost::mutex::scoped_lock mylock ( mymutex );

        clear();
        setHead();

        int countLine = 1;

        list<device>::iterator r = found->begin();

        while ( r != found->end() ) {

            if ( time ( NULL ) > r->getEpoch() + TIMETOLIVE ) {

                list<device>::iterator ex = r;
                r++;
                found->erase ( ex );

            } else {

                printLine ( countLine, r->getMacAddress().to_string(), r->getIpAddress().to_string(), r->getEpoch() );
                r++;

            }

            countLine++;

        }

        mylock.unlock();

        boost::this_thread::sleep ( delay );

    }

}

void scribe ( list<device> *found ) {

    string r_packet;
    getline ( cin,r_packet );
    if ( cin.eof() ) return;

    while ( 1 ) {
        try {

            packet* pkg = packet::factory ( r_packet );

            if ( pkg->isArp() ) {

                boost::mutex::scoped_lock mylock ( mymutex );

                ARPpacket *pkg_arp = dynamic_cast<ARPpacket*> ( pkg );

                bool isFound = false;

                list<device>::iterator p = found->begin();

                while ( p != found->end() ) {

                    if ( p->getMacAddress() == pkg_arp->getSenderMac() && p->getIpAddress() == pkg_arp->getSenderIp() ) {
                        p->setEpoch ( pkg_arp->getEpoch() );
                        isFound = true;
                        break;
                    }

                    p++;
                }

                if ( !isFound ) {
                    device newDevice ( pkg_arp->getSenderMac(), pkg_arp->getSenderIp() );
                    found->push_back ( newDevice );
                }

                mylock.unlock();

            }

            delete pkg;
            getline ( cin,r_packet );
            if ( cin.eof() ) return;

        } catch ( packet::Overflow ) {
            cerr << "Overflow! :-P" << endl;
            endwin();
            return;
        }


    }

}

int main ( int argc, char **argv ) {

    options_description desc ( "Ranging - Network Passive Scanner" );
    desc.add_options()
    ( "help", "prints this" )
    ;

    variables_map vm;
    store ( parse_command_line ( argc, argv, desc ), vm );
    notify ( vm );

    if ( vm.count ( "help" ) ) {
        cout<<desc<<"\n";
        return EXIT_SUCCESS;
    }

    WINDOW *wnd;

    wnd = initscr();	// curses call to initialize window

    if ( !has_colors() ) {
        endwin();
        cerr << "FAIL: Your terminal does not support color." << endl;
        return EXIT_FAILURE;
    }

    start_color();                          // start color mode.
    cbreak();                               // curses call to set no waiting for Enter key
    noecho();                               // curses call to set no echoin
    clear();                                // curses call to clear screen, send cursor to position (0,0)

    getmaxyx ( wnd, rows, cols );
    setHead();

    list<device> found;

    boost::thread scribe_t ( scribe, &found );
    boost::thread printer_t ( printer, &found );

    scribe_t.join();
    printer_t.join();

    endwin();
    return EXIT_SUCCESS;
}

void setHead() {

    char *head;
    int ind1;
    int ind2;

    if ( head = ( char* ) malloc ( cols * sizeof ( char ) ) ) {

        snprintf ( head, cols, " Mac address       | IP address      | Epoch      | TTL" );

        ind2 = strlen ( head );

        for ( ind1 = ind2; ind1 < cols; ind1++ ) {
            head[ind1] = ( int ) ' ';
        }

        head[cols] = ( int ) '\0';
    } else {
        printf ( "FAIL: Memory Allocation Failure\n" );
        return;
    }

    move ( 0, 0 );

    init_pair ( 1, COLOR_BLACK, COLOR_GREEN );

    attron ( COLOR_PAIR ( 1 ) );	// set color for title

    addstr ( head );

    free ( head );

    refresh();

    return;
}

void printLine ( int countLine, string mac, string ip, long int epoch ) {

    int ip_length = ip.length();

    if ( ip_length < 15 ) {

        for ( int ip_filler = 15 - ip_length; ip_filler > 0; ip_filler-- ) {
            ip += ' ';
        }

    }

    char *head;
    int ind1;
    int ind2;

    if ( head = ( char* ) malloc ( cols * sizeof ( char ) ) ) {
        int ttl = TIMETOLIVE - ( time ( NULL ) - epoch );
        snprintf ( head, cols, " %s | %s | %d | %d", mac.c_str(), ip.c_str(), epoch, ttl );

        ind2 = strlen ( head );

        for ( ind1 = ind2; ind1 < cols; ind1++ ) {
            head[ind1] = ( int ) ' ';
        }

        head[cols] = ( int ) '\0';
    } else {
        printf ( "FAIL: Memory Allocation Failure\n" );
        return;
    }

    move ( countLine, 0 );

    init_pair ( 2, COLOR_WHITE, COLOR_BLACK );

    attron ( COLOR_PAIR ( 2 ) );	// set color for title

    addstr ( head );

    free ( head );

    refresh();

    return;
}
