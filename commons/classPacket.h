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

#ifndef LIBHEADER_H
#define LIBHEADER_H

/* EtherType */

#define ETHER_V2_CODE		0x0600	/** Più alto è ethertype, più basso è dimensione */
#define ETHER_TYPE_IPV4		0x0800	/** EtherType IPv4 */
#define ETHER_TYPE_ARP		0x0806	/** EtherType ARP */
#define ETHER_TYPE_IEEE802	0x8100	/** EtherType IEEE 802 */
#define ETHER_TYPE_IPV6		0x86DD	/** EtherType IPv6 */
#define ETHER_TYPE_PPP		0x880B	/** EtherType PPP */

/* ARP */

#define ARP_OFFSET		14	/** Punto dove inizia l'header ARP */

/* IPv4 */

#define IPv4_OFFSET		14	/** Punto dove inizia l'header IPv4 */
#define IPV4_TYPE_ICMP		0x01	/** IPv4 Type ICMP */
#define IPV4_TYPE_TCP		0x06	/** IPv4 Type TCP */
#define IPV4_TYPE_UDP		0x11	/** IPv4 Type UDP */

/* TCP */

#define TCP_OFFSET		34	/** Punto dove inizia l'header TCP */
#define TCP_STANDARD		20 	/** Standard header lenght (byte) */

/* UDP */

#define UDP_OFFSET		34	/** Punto dove inizia l'header UDP */

/* ICMP */

#define ICMPV4_OFFSET		34	/** Punto dove inizia l'header ICMP */
#define ICMPV4_ECHO_REP		0	/** ICMP Type - Echo Reply (PING) */
#define ICMPV4_UNREACH		3	/** ICMP Type - Unreach */
#define ICMPV4_REDIRECT		5	/** ICMP Type - Redirect */
#define ICMPV4_ECHO_REQ		8	/** ICMP Type - Echo Request (PING) */
#define ICMPV4_TRACERT		30	/** ICMP Type - Tracert */

/* INCLUDE */

#include <string>
#include <boost/asio.hpp>
#include <stdint.h>
#include "classMacAddress.h"

namespace libNetwork {

/** Class for managing packets */
class packet
{

protected:

    uint64_t timeEpoch;			/** Timestamp */
    uint32_t timeMillis;		/** Millisecond from timestamp */
    uint32_t pkgLength;			/** Packet length */
    std::string rawData;		/** Raw packet recived from riddle */

    /** Legge n byte a partire dal byte voluto e li restituisce in stringa. */
    std::string getHexString ( int string_cursor, int read_byte );

    /** Legge IPv4 dal byte voluto e restituisce in formato decimale. */
    std::string getDecimalIP ( int string_cursor );

    /** Salva MAC address a partire da un punto (n° del byte) della stringa rawData */
    mac_address getMacAddress ( int string_cursor );

public:

    /** Overflow management */
    class Overflow {};

    /** Class constructor with delayed instantiation*/
    static packet* factory ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i );

    /** Class constructor with delayed instantiation, auto-split mode*/
    static packet* factory ( std::string packetLine );

    /** Virtual destructor */
    virtual ~packet() {}

    /* GENERAL FUNCTIONS */

    /** Returns the packet length in bytes. */
    uint32_t getPacketLength();

    /** Returns packet epoch */
    uint64_t getEpoch();

    /** Returns milliseconds passed from epoch */
    uint32_t getMillis();

    /** true if this is an ARP packet. */
    bool isArp();

    /** true if this is an IPv4 packet. */
    bool isIPv4();

    /** true if this is an IPv6 packet. */
    bool isIPv6();

    /* ETHERNET FUNCTIONS */

    /** returns the mac address of the sender. */
    mac_address getSenderMac();

    /** returns the mac address of the destination. */
    mac_address getTargetMac();

    /** returns ethertype */
    uint16_t getEtherType();

};

/** Class for managing ARP packets */
class ARPpacket : public packet
{

public:

    /** final constructor. */
    ARPpacket ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i );

    /** returns OpCode */
    uint16_t getOpCode();

    /** returns the ip address of the sender. */
    boost::asio::ip::address getSenderIp();

    /** returns the ip address of the destination. */
    boost::asio::ip::address getTargetIp();

};

/** Class for managing IPv4 packets */
class IPv4packet : public packet
{

public:

    /** Class constructor with delayed instantiation */
    static packet* factory ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i );

    /** returns the ip address of the sender. */
    boost::asio::ip::address getSenderIp();

    /** returns the ip address of the destination. */
    boost::asio::ip::address getTargetIp();

    /** returns identity **/
    uint16_t getIdentity();

    /** returns Time To Live **/
    uint16_t getTTL();

    /** returns protocol type */
    uint16_t getProtocolType();

    /** returns checksum */
    uint16_t getIPChecksum();

    /** verify checksum **/
    bool verifyIPChecksum();

    /** returns raw flags. */
    int getFlagsIP();

    /** true if "Don't Fragment" flag is up */
    bool isDF();

    /** true if "More Fragments" flag is up */
    bool isMF();

    /** true if the packet encapsulates a packet TCP. */
    bool isTCP();

    /** true if the packet encapsulates a packet UDP. */
    bool isUDP();

    /** true if the packet encapsulates a packet ICMP. */
    bool isICMP();

};

/** Class for managing TCPv4 packets */
class TCPv4packet : public IPv4packet
{

public:

    /** public flag. use it as you want. */
    bool public_flag;

    /** final constructor. */
    TCPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i );

    /** return the port of the sender. */
    uint16_t getSenderPort();

    /** return the port of the destination. */
    uint16_t getTargetPort();

    /** return sequence number. */
    uint32_t getSequenceNumber();

    /** return acknowledgment number. */
    uint32_t getAcknowledgmentNumber();

    /** return expected acknowledgment number. */
    uint32_t getExpectedAcknowledgmentNumber();

    /** return the TCP header size in bytes. */
    unsigned int getHeaderLength();

    /** return the TCP payload size in bytes. */
    unsigned int getPayloadLength();

    /** returns raw flags. */
    int getFlagsTCP();

    /** return size of the receive window in bytes. */
    unsigned int getWindowSize();

    /** return checksum. */
    unsigned int getTCPChecksum();

    /** return the urgent pointer. */
    unsigned int getUrgentPointer();

    /** return raw TCP option. */
    std::string getOptionRaw();

    /** return TCP option in a std::map */
    std::map<int, std::string> getOptionMap();

    /** return packet payload. */
    std::string getPayLoad();

    /** true if flag ACK is set. */
    bool isACK();

    /** true if flag SYN is set. */
    bool isSYN();

    /** true if flag FIN is set. */
    bool isFIN();

    /** true if flag RST is set. */
    bool isRST();

    /** true if flag PSH is set. */
    bool isPSH();

    /** true if flag URG is set. */
    bool isURG();

    /** true if flag ECE is set. */
    bool isECE();

    /** true if flag CWR is set. */
    bool isCWR();

    /** true if there are additional options. */
    bool isOption();

};

/** Class for managing UDPv4 packets */
class UDPv4packet : public IPv4packet
{

public:

    /** final constructor. */
    UDPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i );

    /** return the port of the sender. */
    uint16_t getSenderPort();

    /** return the port of the destination. */
    uint16_t getTargetPort();

};

/** Class for managing ICMPv4 packets */
class ICMPv4packet : public IPv4packet
{

public:

    /** final constructor. */
    ICMPv4packet ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i );

    /** return message type. */
    uint16_t  getMessageType();

    /** return message code. */
    uint16_t  getMessageCode();

};

/** Class for managing unknown packets */
class UnknownPacket : public packet
{

public:

    /** final constructor. */
    UnknownPacket ( uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i );

};

}

#endif //LIBHEADER_H
