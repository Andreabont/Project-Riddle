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
    for (i=0;i<len;i++) printf("%02x ",start[i]);
    for (i=0;i<(16-len);i++) printf("   ");
    printf("| ");
    for (i=0;i<len;i++)
    {
        if ((start[i]>32)&&(start[i]<128)) printf("%c",start[i]);
        else printf(".");
    }
    printf("\n");
}

void hexDump(const unsigned char *start, struct pcap_pkthdr header)
{
    std::cout<<std::endl<<"[TS: "<<header.ts.tv_sec;
    std::cout<<" uS: "<<header.ts.tv_usec;
    std::cout<<"] Received "<<header.len<<" byte:"<<std::endl;
    int index=0;
    while (header.len>16)
    {
        memPrint(start,16,index);
        header.len-=16;
        start+=16;
        index+=16;
    }
    if (header.len>0) memPrint(start,header.len,index);
}

void rawDump(const unsigned char *start, struct pcap_pkthdr header)
{
    std::cout<<header.ts.tv_sec<<"!";
    std::cout<<header.ts.tv_usec<<"!";
    for (int i=0;i<header.len;i++) printf("%02x",start[i]);
    std::cout<<std::endl;
}
