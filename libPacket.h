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

/* ARP */

#define ARP_OFFSET		14

/* IPv4 */

#define IPv4_OFFSET		14 
#define IPV4_TYPE_ICMP		0x01
#define IPV4_TYPE_TCP		0x06
#define IPV4_TYPE_UDP		0x11

/* TCP */

#define TCP_OFFSET		34
#define TCP_STANDARD		20 	// Standard header lenght (byte)

/* UDP */

#define UDP_OFFSET		34

/* ICMP */

#define ICMPV4_OFFSET		34
#define ICMPV4_ECHO_REP		0
#define ICMPV4_UNREACH		3
#define ICMPV4_REDIRECT		5
#define ICMPV4_ECHO_REQ		8
#define ICMPV4_TRACERT		30

/* INCLUDE */

#include <string>
#include <boost/asio.hpp>
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

    /* Overflow management */
    class Overflow {};

    /* Class constructor with delayed instantiation*/
    static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    
    /* Virtual destructor */
    virtual ~packet() {}

/* GENERAL FUNCTIONS */

    /* Returns the packet length in bytes. */
    int getLength();

    /* Returns packet epoch */
    long int getEpoch();

    /* Returns milliseconds passed from epoch */
    int getMillis();

    /* Legge n byte a partire dal byte voluto e li restituisce in stringa. */
    std::string getHexString(int string_cursor, int read_byte);

    /* Legge IPv4 dal byte voluto e restituisce in formato decimale. */
    std::string decodeIPaddress(int string_cursor);

    /* Salva MAC address a partire da un punto (n° del byte) della stringa rawData */
    mac_address getMacAddress(int string_cursor);

    /* Salva IPv4 address a partire da un punto (n° del byte) della stringa rawData */
    boost::asio::ip::address getIPv4Address(int string_cursor);

    /* True se e' un pacchetto ARP */
    bool isArp();

    /* True se e' un pacchetto IPv4 */
    bool isIPv4();

    /* True se e' un pacchetto IPv6*/
    bool isIPv6();

    /* ETHERNET FUNCTIONS */

    /* Restituisce MAC della scheda di rete che ha inviato la trama*/
    mac_address getSenderMac();

    /* Restituisce MAC del destinatario della trama*/
    mac_address getTargetMac();

    /*Restituisce ethertype*/
    unsigned int getEtherType();

};

/*Class for managing ARP packets*/
class ARPpacket : public packet
{
public:
    ARPpacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    unsigned int getOpCode();
    boost::asio::ip::address getSenderIp();
    boost::asio::ip::address getTargetIp();
};

/*Class for managing IPv4 packets*/
class IPv4packet : public packet
{
public:
    static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    boost::asio::ip::address getSenderIp();
    boost::asio::ip::address getTargetIp();
    unsigned int getProtocolType();
    bool isTCP();
    bool isUDP();
    bool isICMP();
};

/*Class for managing TCPv4 packets*/
class TCPv4packet : public IPv4packet
{
public:
    TCPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    unsigned int getSenderPort();
    unsigned int getTargetPort();
    unsigned int getSequenceNumber();
    unsigned int getAcknowledgmentNumber();
    unsigned int getHeaderLength();
    int getFlags();
    unsigned int getWindowSize();
    unsigned int getChecksum();
    unsigned int getUrgentPointer();
    std::string getTcpOption();
    std::string getPayLoad();
    bool isACK();
    bool isSYN();
    bool isFIN();
    bool isRST();
    bool isPSH();
    bool isURG();
    bool isECE();
    bool isCWR();
};

/*Class for managing UDPv4 packets*/
class UDPv4packet : public IPv4packet
{
public:
    UDPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    unsigned int getSenderPort();
    unsigned int getTargetPort();
};

/*Class for managing ICMPv4 packets*/
class ICMPv4packet : public IPv4packet
{
public:
    ICMPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    unsigned int getMessageType();
    unsigned int getMessageCode();
};

/*Class for managing unknown packets*/
class UnknownPacket : public packet
{
public:
    UnknownPacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

#endif //LIBHEADER_H
