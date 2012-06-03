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

#include <curses.h>
#include "./commons/libAddress.h"
#include "./commons/libPacket.h"
#include "./libraries/libRanging.h"

#define TIMETOLIVE 50
#define THRESHOLD 1

int rows; // number of rows in window
int cols; // number of columns in window

using namespace std;
using namespace boost;
using namespace boost::program_options;
using namespace boost::gregorian;
using namespace boost::posix_time;
using namespace libNetwork;

void setHead();
void printLine(int countLine, string mac, string ip, long int epoch, long int lastEpoch);

int main(int argc, char **argv) {

    options_description desc("Ranging - Network Passive Scanner");
    desc.add_options()
    ("help", "prints this")
    ;

    variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if (vm.count("help"))
    {
        cout<<desc<<"\n";
        return EXIT_SUCCESS;
    }

    string r_packet;
    getline(cin,r_packet);
    if (cin.eof()) return EXIT_SUCCESS;

    WINDOW *wnd;

    wnd = initscr();	// curses call to initialize window

    if (!has_colors())
    {
        endwin();
        cerr << "FAIL: Your terminal does not support color." << endl;
        return EXIT_FAILURE;
    }

    start_color();                          // start color mode.
    cbreak();                               // curses call to set no waiting for Enter key
    noecho();                               // curses call to set no echoin
    clear();                                // curses call to clear screen, send cursor to position (0,0)

    getmaxyx(wnd, rows, cols);
    setHead();

    list<device> found;

    long int lastEpoch = 0;

    bool refresh_display;

    while (1)
    {
        try
        {

            packet* pkg = packet::factory(r_packet);

            refresh_display = (pkg->getEpoch() - lastEpoch > THRESHOLD);

            lastEpoch = pkg->getEpoch();

            if(pkg->isArp())
            {
                ARPpacket *pkg_arp = dynamic_cast<ARPpacket*>(pkg);

                bool isFound = false;

                list<device>::iterator p = found.begin();

                while(p != found.end())
                {

                    if(p->getMacAddress() == pkg_arp->getSenderMac() && p->getIpAddress() == pkg_arp->getSenderIp())
                    {
                        p->setEpoch(lastEpoch);
                        isFound = true;
                        break;
                    }

                    p++;
                }

                if(!isFound)
                {
                    device newDevice(pkg_arp->getSenderMac(), pkg_arp->getSenderIp(), lastEpoch);
                    found.push_back(newDevice);
                }
            }

            list<device>::iterator q = found.begin();

            while(q != found.end())
            {
                if(lastEpoch >= q->getEpoch() + TIMETOLIVE)
                {
                    q = found.erase(q);
                }

                q++;
            }

            delete pkg;
            getline(cin,r_packet);
            if (cin.eof()) break;

        }
        catch (packet::Overflow)
        {
            cerr << "Overflow! :-P" << endl;
            endwin();
            return EXIT_FAILURE;
        }

        if(refresh_display)
        {

            clear();
            setHead();

            int countLine = 1;

            list<device>::iterator r = found.begin();

            while(r != found.end()) {

                printLine(countLine, r->getMacAddress().to_string(), r->getIpAddress().to_string(), r->getEpoch(), lastEpoch);

                countLine++;
                r++;
            }
        }

    }
    endwin();
    return EXIT_SUCCESS;
}

void setHead()
{

    char *head;
    int ind1;
    int ind2;

    if(head = (char*)malloc(cols * sizeof(char)))
    {

        snprintf(head, cols, " Mac address       | IP address      | Epoch      | TTL");

        ind2 = strlen(head);

        for (ind1 = ind2; ind1 < cols; ind1++)
        {
            head[ind1] = (int)' ';
        }

        head[cols] = (int)'\0';
    }
    else
    {
        printf("FAIL: Memory Allocation Failure\n");
        return;
    }

    move(0, 0);

    init_pair(1, COLOR_BLACK, COLOR_GREEN);

    attron(COLOR_PAIR(1));	// set color for title

    addstr(head);

    free(head);

    refresh();

    return;
}

void printLine(int countLine, string mac, string ip, long int epoch, long int lastEpoch)
{

    int ip_length = ip.length();

    if(ip_length < 15)
    {

        for(int ip_filler = 15 - ip_length; ip_filler > 0; ip_filler--)
        {
            ip += ' ';
        }

    }

    char *head;
    int ind1;
    int ind2;

    if(head = (char*)malloc(cols * sizeof(char)))
    {
        int ttl = TIMETOLIVE - (lastEpoch - epoch);
        snprintf(head, cols, " %s | %s | %d | %d", mac.c_str(), ip.c_str(), epoch, ttl );

        ind2 = strlen(head);

        for (ind1 = ind2; ind1 < cols; ind1++)
        {
            head[ind1] = (int)' ';
        }

        head[cols] = (int)'\0';
    }
    else
    {
        printf("FAIL: Memory Allocation Failure\n");
        return;
    }

    move(countLine, 0);

    init_pair(2, COLOR_WHITE, COLOR_BLACK);

    attron(COLOR_PAIR(2));	// set color for title

    addstr(head);

    free(head);

    refresh();

    return;
}

