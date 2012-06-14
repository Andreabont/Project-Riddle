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

#include "libRanging.h"

device::device ( libNetwork::mac_address newMac, boost::asio::ip::address newIp, long int newEpoch ) {
    mac = newMac;
    ip = newIp;
    timeEpoch = newEpoch;
    return;
}

boost::asio::ip::address device::getIpAddress() {
    return ip;
}

libNetwork::mac_address device::getMacAddress() {
    return mac;
}

long int device::getEpoch() {
    return timeEpoch;
}

void device::setEpoch ( long int newEpoch ) {
    timeEpoch = newEpoch;
    return;
}
