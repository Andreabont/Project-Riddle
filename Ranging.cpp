//============================================================================
// Name        : Riddle
// Author      : Andrea Bontempi
// Version     : 0.1
// Copyright   : GNU GPL3
// Description : Network Sniffer
//
// Special Thanks to fede.tft for the big help :-)
//
//============================================================================

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <iomanip>
#include <list>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

#include <curses.h>
#include "libAddress.h"
#include "libPacket.h"
#include "libRanging.h"

int rows; // number of rows in window
int cols; // number of columns in window

using namespace std;
using namespace boost;
using namespace boost::program_options;

void setHead();
void printLine(int countLine, string mac, string ip, int epoch);

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

    WINDOW *wnd;

    wnd = initscr();	// curses call to initialize window

    if (has_colors() == FALSE)
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

    while (1)
    {
        try
        {
            string r_packet;
            getline(cin,r_packet);
            if (cin.eof()) break;

            std::vector< std::string > line;
            boost::algorithm::split(line, r_packet, boost::algorithm::is_any_of("!"));

            packet* pkg = packet::factory(lexical_cast<int>(line[0]), lexical_cast<int>(line[1]), line[2]);

            if(pkg->isArp())
            {
                ARPpacket *pkg_arp = dynamic_cast<ARPpacket*>(pkg);

                list<device>::iterator p = found.begin();

                bool isFound = false;

                while(p != found.end())
                {

                    if(p->getMacAddress() == pkg_arp->getSenderMac() && p->getIpAddress() == pkg_arp->getSenderIp())
                    {
                        p->setEpoch(pkg_arp->getEpoch());
                        isFound = true;
                        break;
                    }

                    p++;
                }

                if(!isFound)
                {
                    device newDevice(pkg_arp->getSenderMac(), pkg_arp->getSenderIp(), pkg_arp->getEpoch());
                    found.push_back(newDevice);
                }
            } 

            delete pkg;

        }
        catch (packet::Overflow)
        {
            cerr << "Overflow! :-P" << endl;
            endwin();
            return EXIT_FAILURE;
        }

        clear();
        setHead();

        int countLine = 1;

        list<device>::iterator q = found.begin();
        while(q != found.end()) {

            printLine(countLine, q->getMacAddress().to_string(), q->getIpAddress().to_string(), q->getEpoch());

            countLine++;
            q++;
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

        snprintf(head, cols, " Mac address       | IP address      | Epoch");

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

void printLine(int countLine, string mac, string ip, int epoch)
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
        snprintf(head, cols, " %s | %s | %d", mac.c_str(), ip.c_str(), epoch);

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

