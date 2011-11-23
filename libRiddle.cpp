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

#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include "libRiddle.h"

// Non mettere using namespace generali in header file.

void pcap_fatal(const char *error_in, const char *error_buffer)
{
	std::stringstream ss;
	ss<<"Fatal Error in "<<error_in<<": "<<error_buffer;
	throw(std::runtime_error(ss.str()));
}

static void memPrint(const unsigned char *start, char len, int index)
{
	printf("0x%08x | ",index);
	int i;
	for(i=0;i<len;i++) printf("%02x ",start[i]);
	for(i=0;i<(16-len);i++) printf("   ");
	printf("| ");
	for(i=0;i<len;i++)
	{
		if((start[i]>32)&&(start[i]<128)) printf("%c",start[i]);
		else printf(".");
	}
	printf("\n");
}

void hexDump(const unsigned char *start, int len)
{
	std::cout<<std::endl<<"Received "<<len<<" byte:"<<std::endl;
	int index=0;
	while(len>16)
	{
		memPrint(start,16,index);
		len-=16;
		start+=16;
		index+=16;
	}
	if(len>0) memPrint(start,len,index);
}

void rawDump(const unsigned char *start, int len)
{
	for(int i=0;i<len;i++) printf("%02x",start[i]);
	printf("\n");
}
