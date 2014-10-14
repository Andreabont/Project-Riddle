/* 
 * File:   thread_scribe.cpp
 * Author: andreabont
 *
 * Created on 25 gennaio 2014, 10.45
 */

#include <iostream>
#include <memory>
#include <curses.h>
#include "thread.h"
#include "commons/packet.h"
#include "commons/macaddress.h"


using namespace std;
using namespace network;

void scribe(list<device> *found) {

    string r_packet;
    getline(cin, r_packet);
    if (cin.eof()) return;

    while (1) {
        try {

	    shared_ptr<packet> pkg = packet::factory ( r_packet );

            if (pkg->isArp()) {

                boost::mutex::scoped_lock scribe_lock(mymutex);

		shared_ptr<ARPpacket> pkg_arp = dynamic_pointer_cast< ARPpacket > ( pkg );

                bool isFound = false;

		for(auto deviceObj = found->begin(); deviceObj != found->end();  deviceObj++) {
		    if (deviceObj->getMacAddress() == pkg_arp->getSenderMac() && deviceObj->getIpAddress() == pkg_arp->getSenderIp()) {
                        deviceObj->setEpoch(pkg_arp->getEpoch());
                        isFound = true;
                        break;
                    }
		}

                if (!isFound) {
                    device newDevice(pkg_arp->getSenderMac(), pkg_arp->getSenderIp());
                    found->push_back(newDevice);
                }

                scribe_lock.unlock();

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