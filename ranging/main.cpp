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

#ifdef __linux__
#include <signal.h>
#endif

#include "commons/macaddress.h"
#include "commons/packet.h"
#include "tools.h"

#define TIMETOLIVE 120

using namespace std;
using namespace boost::program_options;
using namespace boost::gregorian;
using namespace boost::posix_time;
using namespace network;

#ifdef __linux__
void exit_signal ( int id ) {
    cerr << ">> Exit signal detected. (" << id << ")" << endl;
    endwin();
    exit ( 0 );
}
#endif

boost::mutex mymutex;
int maxttl = TIMETOLIVE;

/** The thread "printer" manages the display. */
void printer(list<device> *found, win_size winxy);

/** The thread "scribe" listens to incoming packets. */
void scribe(list<device> *found);

int main(int argc, char **argv) {
    
    #ifdef __linux__
    signal ( SIGINT, exit_signal );     /* Ctrl-C */
    signal ( SIGQUIT, exit_signal );    /* Ctrl-\ */
    #endif

    options_description desc("Ranging - Network Passive Scanner");
    desc.add_options()
            ("help,h", "prints this")
            ("ttl,t", value<int>(), "sets the deadline (in seconds) for each match (default = 50)")
            ;

    variables_map vm;

    try {
        store(parse_command_line(argc, argv, desc), vm);
        notify(vm);
    } catch (boost::program_options::unknown_option ex1) {
        cerr << "ERROR >> " << ex1.what() << "" << endl;
        cerr << ">> Try '" << argv[0] << " --help' for more information." << endl;
        return EXIT_SUCCESS;
    } catch (boost::program_options::invalid_command_line_syntax ex2) {
        cerr << "ERROR >> " << ex2.what() << "" << endl;
        cerr << ">> Try '" << argv[0] << " --help' for more information." << endl;
        return EXIT_SUCCESS;
    }

    if (vm.count("help")) {
        cout << desc << "\n";
        return EXIT_SUCCESS;
    }

    if (vm.count("ttl")) {
        maxttl = vm["ttl"].as<int>();
    }

    WINDOW *wnd;

    wnd = initscr(); // curses call to initialize window

    if (!has_colors()) {
        endwin();
        cerr << "FAIL: Your terminal does not support color." << endl;
        return EXIT_FAILURE;
    }

    start_color(); // start color mode.
    cbreak(); // curses call to set no waiting for Enter key
    noecho(); // curses call to set no echoin
    clear(); // curses call to clear screen, send cursor to position (0,0)

    win_size winxy;
    getmaxyx(wnd, winxy.rows, winxy.cols);
    
    setHead(winxy);

    list<device> found;

    boost::thread scribe_t(scribe, &found);
    boost::thread printer_t(printer, &found, winxy);

    scribe_t.join();
    printer_t.join();

    endwin();
    return EXIT_SUCCESS;
}

void printer(list<device> *found, win_size winxy) {

    static boost::posix_time::seconds delay(1);

    while (1) {

        boost::mutex::scoped_lock mylock(mymutex);

        clear();
        setHead(winxy);

        int countLine = 1;

        list<device>::iterator r = found->begin();

        while (r != found->end()) {

            if (time(NULL) > r->getEpoch() + maxttl) {

                list<device>::iterator ex = r;
                r++;
                found->erase(ex);

            } else {

                printLine(winxy, countLine, maxttl, r);
                r++;

            }

            countLine++;

        }

        mylock.unlock();

        boost::this_thread::sleep(delay);

    }

}

void scribe(list<device> *found) {

    string r_packet;
    getline(cin, r_packet);
    if (cin.eof()) return;

    while (1) {
        try {

	    shared_ptr<packet> pkg = packet::factory ( r_packet );

            if (pkg->isArp()) {

                boost::mutex::scoped_lock mylock(mymutex);

		shared_ptr<ARPpacket> pkg_arp = dynamic_pointer_cast< ARPpacket > ( pkg );

                bool isFound = false;

                list<device>::iterator p = found->begin();

                while (p != found->end()) {

                    if (p->getMacAddress() == pkg_arp->getSenderMac() && p->getIpAddress() == pkg_arp->getSenderIp()) {
                        p->setEpoch(pkg_arp->getEpoch());
                        isFound = true;
                        break;
                    }

                    p++;
                }

                if (!isFound) {
                    device newDevice(pkg_arp->getSenderMac(), pkg_arp->getSenderIp());
                    found->push_back(newDevice);
                }

                mylock.unlock();

            }

            getline(cin, r_packet);
            if (cin.eof()) return;

        } catch (packet::Overflow) {
            cerr << "Overflow! :-P" << endl;
            endwin();
            return;
        }


    }

}