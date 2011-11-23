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

void pcap_fatal(const char *error_in, const char *error_buffer);
void hexDump(const unsigned char *start, int len);
void rawDump(const unsigned char *start, int len);

#endif //LIBRIDDLE_H
