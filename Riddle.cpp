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
#include <limits>
#include <pcap.h>
#include <boost/program_options.hpp>
#include "libRiddle.h"

using namespace std;
using namespace boost::program_options;

int main(int argc, char **argv) {
    options_description desc("Riddle - Network Sniffer");
    desc.add_options()
    ("help", "prints this")
    ("dump", "enable dump mode")
    ("iface", value<string>(), "interface to sniff from (not set = default device)")
    ("input", value<string>(), "reads packets from a pcap file (disable iface input)")
    ("filter", value<string>(), "use to filter packet with bpf")
    ("limit", value<int>(), "set max number of packet")
    ;

    variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if (vm.count("help"))
    {
        cout<<desc<<"\n";
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *pcap_handle;

    if(vm.count("input"))
    {
        pcap_handle = pcap_open_offline(vm["input"].as<string>().c_str(), error_buffer);
        if (pcap_handle == NULL) {
            pcap_fatal("pcap_open_live", error_buffer);
        }

        cerr<<">> Reading packets from "<<vm["input"].as<string>()<<endl;
    }
    else
    {

        string pcap_device;

        if (vm.count("iface"))
        {
            pcap_device=vm["iface"].as<string>();
        } else {
            // Cerca e restituisce interfaccia
            char *dev=pcap_lookupdev(error_buffer);
            if (dev!=NULL) pcap_device = dev;
            else pcap_fatal("pcap_lookupdev", error_buffer);
        }

        // Apre il device in mod promiscua
        pcap_handle = pcap_open_live(pcap_device.c_str(), 4096, 1, 0, error_buffer);
        if (pcap_handle == NULL) {
            pcap_fatal("pcap_open_live", error_buffer);
        }

        cerr<<">> Sniffing on device "<<pcap_device<<endl;

    }

    if (vm.count("filter"))
    {
        string filter = vm["filter"].as<string>();
        struct bpf_program fp;
        bpf_u_int32 net;

        cerr<<">> Filtering with '"<<filter<<"'"<<endl;

        if (pcap_compile(pcap_handle, &fp, filter.c_str(), 0, net) == -1)
        {
            cerr<< ">> Couldn't parse filter '"<<filter<<"': "<<pcap_geterr(pcap_handle)<<endl;
            return(2);
        }

        if (pcap_setfilter(pcap_handle, &fp) == -1) {
            cerr<< ">> Couldn't install filter '"<<filter<<"': "<<pcap_geterr(pcap_handle)<<endl;
            return(2);
        }
    }

    int maxpacket = numeric_limits<int>::max();

    if (vm.count("limit"))
    {
        maxpacket=vm["limit"].as<int>();
    }

    void (*dumper)(const unsigned char*,struct pcap_pkthdr);
    if (vm.count("dump")) dumper=hexDump;
    else dumper=rawDump;

    const u_char *packet;
    pcap_pkthdr header;

    for (; maxpacket > 0;)
    {
        packet = pcap_next(pcap_handle, &header);
        if(packet == NULL)
        {
            cerr<<">> Flow terminated"<<endl;
            break;
        }
        dumper(packet, header);
        if (maxpacket!=numeric_limits<int>::max()) maxpacket--;
    }

    cerr<<">> I finished the job, goodbye!"<<endl;
    pcap_close(pcap_handle);

    return EXIT_SUCCESS;
}
