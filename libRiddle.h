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
void hexDump(const unsigned char *start, struct pcap_pkthdr header);
void rawDump(const unsigned char *start, struct pcap_pkthdr header);

#endif //LIBRIDDLE_H
