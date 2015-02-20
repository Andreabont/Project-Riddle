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

#include <sys/time.h>
#include <curses.h>
#include <string>
#include <list>
#include "tools.h"

device::device(network::mac_address newMac, boost::asio::ip::address newIp) {
    mac = newMac;
    ip = newIp;
    timeEpoch = time(NULL);
    return;
}

boost::asio::ip::address device::getIpAddress() {
    return ip;
}

network::mac_address device::getMacAddress() {
    return mac;
}

long int device::getEpoch() {
    return timeEpoch;
}

void device::setEpoch(long int newEpoch) {
    timeEpoch = newEpoch;
    return;
}

void setHead(win_size winxy) {

    char *head;
    int ind1;
    int ind2;

    if (head = (char*) malloc(winxy.cols * sizeof ( char))) {

        snprintf(head, winxy.cols, " Mac address       | IP address      | Epoch      | TTL");

        ind2 = strlen(head);

        for (ind1 = ind2; ind1 < winxy.cols; ind1++) {
            head[ind1] = (int) ' ';
        }

        head[winxy.cols] = (int) '\0';
    } else {
        printf("FAIL: Memory Allocation Failure\n");
        return;
    }

    move(0, 0);

    init_pair(1, COLOR_BLACK, COLOR_GREEN);

    attron(COLOR_PAIR(1)); // set color for title

    addstr(head);

    free(head);

    refresh();

    return;
}

void printLine(win_size winxy, int countLine, int maxttl, std::list<device>::iterator dev) {

    std::string ip = dev->getIpAddress().to_string();
    std::string mac = dev->getMacAddress().to_string();
    long int epoch = dev->getEpoch();

    int ip_length = ip.length();

    if (ip_length < 15) {

        for (int ip_filler = 15 - ip_length; ip_filler > 0; ip_filler--) {
            ip += ' ';
        }

    }

    char *head;
    int ind1;
    int ind2;

    if (head = (char*) malloc(winxy.cols * sizeof ( char))) {
        int ttl = maxttl - (time(NULL) - epoch);
        snprintf(head, winxy.cols, " %s | %s | %ld | %d", mac.c_str(), ip.c_str(), epoch, ttl);

        ind2 = strlen(head);

        for (ind1 = ind2; ind1 < winxy.cols; ind1++) {
            head[ind1] = (int) ' ';
        }

        head[winxy.cols] = (int) '\0';
    } else {
        printf("FAIL: Memory Allocation Failure\n");
        return;
    }

    move(countLine, 0);

    init_pair(2, COLOR_WHITE, COLOR_BLACK);

    attron(COLOR_PAIR(2)); // set color for title

    addstr(head);

    free(head);

    refresh();

    return;
}
