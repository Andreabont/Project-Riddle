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

/* EtherType */

#define ETHER_V2_CODE		0x0600
#define ETHER_TYPE_IPV4		0x0800
#define ETHER_TYPE_ARP		0x0806
#define ETHER_TYPE_IEEE802	0x8100
#define ETHER_TYPE_IPV6		0x86DD
#define ETHER_TYPE_PPP		0x880B

/* IP */

#define IPV4_TYPE_TCP		0x06
#define IPV4_TYPE_UDP		0x11

/* ARP */

#define ARP_OFFSET		20

/* INCLUDE */

#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include "libAddress.h"

/* Class for managing packets*/
class packet
{
  
  protected:
    std::string rawData;
    long int timeEpoch;
    int timeMillis;
    int pkgLength;
  
  public:
    
    class Overflow {}; // Gestore overflow.
    class HeaderFault {}; // Gestore header sbagliato.
    
    /* Costruttore Pacchetto */
    static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    
    /* GENERAL FUNCTIONS */
    
    /* Ottieni lunghezza in byte */
    int getLength();
    
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
    
    /* ETHERNET FUNCTIONS */
    
};

/*Class for managing ARP packets*/
class ARPpacket : public packet
{
    public:
      ARPpacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
      int getOpCode();
      mac_address getSenderMac();
      mac_address getTargetMac();
      boost::asio::ip::address getSenderIp();
      boost::asio::ip::address getTargetIp();
};

/*Class for managing IPv4 packets*/
class IPv4packet : public packet
{
    public:
      static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

/*Class for managing TCPv4 packets*/
class TCPv4packet : public IPv4packet
{
    public:
      static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

/*Class for managing UDPv4 packets*/
class UDPv4packet : public IPv4packet
{
    public:
      static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

/*Class for managing unknown packets*/
class UnknownPacket : public packet
{
    public:
      UnknownPacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

/*Class for managing unknown TCPv4 packets*/
class UnknownTCP : public TCPv4packet
{
    public:
      UnknownTCP(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

/*Class for managing unknown UDPv4 packets*/
class UnknownUDP : public TCPv4packet
{
    public:
      UnknownUDP(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

#endif //LIBHEADER_H