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
 *  Foobar is free software: you can redistribute it and/or modify
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

#ifndef LIBRIDDLE_H
#define LIBRIDDLE_H

#include <pcap.h>

/*  struct pcap_pkthdr {
 * struct timeval ts;   time stamp
 * bpf_u_int32 caplen;  length of portion present
 * bpf_u_int32;         lebgth this packet (off wire)
 } *
 */

void pcap_fatal(const char *error_in, const char *error_buffer);

/* Funzioni per la stampa su schermo dei dati in formato esadecimale */
void hexDump(const unsigned char *start, struct pcap_pkthdr header);
void rawDump(const unsigned char *start, struct pcap_pkthdr header);

#endif //LIBRIDDLE_H
