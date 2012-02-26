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

#ifndef LIBHEADER_H
#define LIBHEADER_H

#define ETHER_V2_CODE		0x0600
#define ETHER_TYPE_IPV4		0x0800
#define ETHER_TYPE_ARP		0x0806
#define ETHER_TYPE_IEEE802	0x8100
#define ETHER_TYPE_IPV6		0x86DD
#define ETHER_TYPE_PPP		0x880B

#define IPV4_TYPE_TCP		0x06
#define IPV4_TYPE_UDP		0x11

#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include "libAddress.h"

/* Class for managing packets*/
class packet
{
  
  private:
    std::string rawData;
    long int timeEpoch;
    int timeMillis;
    int pkgLength;
  
  public:
    
    class Overflow {}; // Gestore overflow.
    class HeaderFault {}; // Gestore header sbagliato.
    
    /* Costruttore Pacchetto */
    static packet* factory(std::string rawInput);
    
    /* Ottieni lunghezza in byte */
    int getLenght();
    
    /* Ottieni epoch */
    long int getEpoch();
    
    /* Ottienti millisecondi passati dopo epoch */
    int getMillis();
    
    /* Legge n byte a partire dal byte voluto e li restituisce in stringa. */
    std::string getHexString(int string_cursor, int read_byte);
    
    /* Salva MAC address a partire da un punto della stringa rawData */
    mac_address getMacAddress(int string_cursor);
    
    /* Salva IPv4 address a partire da un punto della stringa rawData */
    boost::asio::ip::address getIPv4Address(int string_cursor);
    
    /* True se e' un pacchetto ARP */
    bool isArp();
    
    /* True se e' un pacchetto IPv4 */
    bool isIPv4();
    
    /* True se e' un pacchetto IPv6*/
    bool isIPv6();
    
};

/*Class for managing ARP packets*/
class ARPpacket : public packet
{
    
};

/*Class for managing IPv4 packets*/
class IPv4packet : public packet
{
  
};

/*Class for managing IPv6 packets*/
class IPv6packet : public packet
{
  
};

/*Class for managing TCPv4 packets*/
class TCPv4packet : public IPv4packet
{
  
};

/*Class for managing UDPv4 packets*/
class UDPv4packet : public IPv4packet
{
  
};

class UnknownPacket : public packet
{
  
};

#endif //LIBHEADER_H