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
#include "libAddress.h"

/** Class for managing packets */
class packet
{

protected:
    std::string rawData;		/** Raw packet recived from riddle */
    long int timeEpoch;			/** Timestamp */
    int timeMillis;			/** Millisecond from timestamp */
    int pkgLength;			/** Packet length */

public:

    /** Overflow management */
    class Overflow {};

    /** Class constructor with delayed instantiation*/
    static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);

    /** Virtual destructor */
    virtual ~packet() {}

    /* GENERAL FUNCTIONS */

    /** Returns the packet length in bytes. */
    int getPacketLength();

    /** Returns packet epoch */
    long int getEpoch();

    /** Returns milliseconds passed from epoch */
    int getMillis();

    /** Legge n byte a partire dal byte voluto e li restituisce in stringa. */
    std::string getHexString(int string_cursor, int read_byte);

    /** Legge IPv4 dal byte voluto e restituisce in formato decimale. */
    std::string getDecimalIP(int string_cursor);

    /** Salva MAC address a partire da un punto (n° del byte) della stringa rawData */
    mac_address getMacAddress(int string_cursor);

    /** Salva IPv4 address a partire da un punto (n° del byte) della stringa rawData */
    boost::asio::ip::address getIPv4Address(int string_cursor);

    /** True se e' un pacchetto ARP */
    bool isArp();

    /** True se e' un pacchetto IPv4 */
    bool isIPv4();

    /** True se e' un pacchetto IPv6*/
    bool isIPv6();

    /* ETHERNET FUNCTIONS */

    /** Restituisce MAC della scheda di rete che ha inviato la trama*/
    mac_address getSenderMac();

    /** Restituisce MAC del destinatario della trama*/
    mac_address getTargetMac();

    /** Restituisce ethertype */
    unsigned int getEtherType();

};

/** Class for managing ARP packets */
class ARPpacket : public packet
{
public:
  
    /** Costruttore finale */
    ARPpacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
    
    /** Ritorna OpCode */
    unsigned int getOpCode();
    
    /** Ritorna indirizzo IP del mittente */
    boost::asio::ip::address getSenderIp();
    
    /** Ritorna indirizzo IP del destinatario */
    boost::asio::ip::address getTargetIp();
};

/** Class for managing IPv4 packets */
class IPv4packet : public packet
{
public:

    /** Class constructor with delayed instantiation */
    static packet* factory(int timeEpoch_i, int timeMillis_i, std::string rawData_i);

    /** Ritorna indirizzo IP del mittente */
    boost::asio::ip::address getSenderIp();

    /** Ritorna indirizzo IP del destinatario */
    boost::asio::ip::address getTargetIp();

    /** Ritorna il tipo di protocollo incapsulato */
    unsigned int getProtocolType();
    
    /** Ritorna checksum */
    unsigned int getIPChecksum();
    
    /** Verify checksum **/
    bool verifyIPChecksum();

    /** True se incapsula un pacchetto TCP */
    bool isTCP();

    /** True se incapsula un pacchetto UDP */
    bool isUDP();

    /** True se incapsula un pacchetto ICMP */
    bool isICMP();
};

/** Class for managing TCPv4 packets */
class TCPv4packet : public IPv4packet
{
public:

    /** Costruttore finale */
    TCPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i);

    /** Restituisce porta TCP del mittente */
    unsigned int getSenderPort();

    /** Restituisce porta TCP del destinatario */
    unsigned int getTargetPort();

    /** Restituisce il numero di sequenza */
    unsigned int getSequenceNumber();

    /** Restituisce il numero di acknowledgment */
    unsigned int getAcknowledgmentNumber();

    /** Ritorna dimensione dell'header TCP in byte */
    unsigned int getHeaderLength();

    /** Ritorna i flag TCP in formato raw, da processare */
    int getFlags();

    /** Ritorna dimensione della finestra di ricezione */
    unsigned int getWindowSize();

    /** Ritorna checksum */
    unsigned int getTCPChecksum();
    
    /** Verify checksum **/
    bool verifyTCPChecksum();
    
    /** Ritorna l'urgent pointer */
    unsigned int getUrgentPointer();

    /** Ritorna le opzioni TCP in formato raw, da processare */
    std::string getOptionRaw();

    /** Ritorna le opzioni TCP in una std::map */
    std::map<int, std::string> getOptionMap();

    /** Ritorna i dati trasportati dal pacchetto TCP */
    std::string getPayLoad();

    /** True se ha flag ACK */
    bool isACK();

    /** True se ha flag SYN */
    bool isSYN();

    /** True se ha flag FIN */
    bool isFIN();

    /** True se ha flag RST */
    bool isRST();

    /** True se ha flag PSH */
    bool isPSH();

    /** True se ha flag URG */
    bool isURG();

    /** True se ha flag ECE */
    bool isECE();

    /** True se ha flag CWR */
    bool isCWR();

    /** True se sono presenti delle opzioni aggiuntive */
    bool isOption();
};

/** Class for managing UDPv4 packets */
class UDPv4packet : public IPv4packet
{
public:

    /** Costruttore finale */
    UDPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i);

    /** Ritorna porta UDP del mittente */
    unsigned int getSenderPort();

    /** Ritorna porta UDP del destinatario */
    unsigned int getTargetPort();
};

/** Class for managing ICMPv4 packets */
class ICMPv4packet : public IPv4packet
{
public:

    /** Costruttore finale */
    ICMPv4packet(int timeEpoch_i, int timeMillis_i, std::string rawData_i);

    /** Ritorna il tipo di messaggio ICMP */
    unsigned int getMessageType();

    /** Ritorna il MessageCode */
    unsigned int getMessageCode();
};

/** Class for managing unknown packets */
class UnknownPacket : public packet
{
public:

    /** Costruttore finale */
    UnknownPacket(int timeEpoch_i, int timeMillis_i, std::string rawData_i);
};

#endif //LIBHEADER_H
