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

#ifndef PACKET_H
#define PACKET_H

/** Offset */

namespace offset {
    const uint8_t ARP           = 14; /** ARP Offset */
    const uint8_t IPV4          = 14; /** IPv4 Offset */
    const uint8_t TCP           = 34; /** TCP Offset */
    const uint8_t UDP           = 34; /** UDP Offset */
    const uint8_t ICMPV4        = 34; /** ICMPv4 Offsets */
}

/* EtherType */

namespace ethertype {
    const uint16_t V2_CODE      = 0x0600; /** EtherType: Below this value means "length" */
    const uint16_t IPV4         = 0x0800; /** EtherType: IPv4 */
    const uint16_t ARP          = 0x0806; /** EtherType: Address Resolution Protocol */
    const uint16_t WOL          = 0x0842; /** EtherType: Wake-On-Lan */
    const uint16_t RARP         = 0x8035; /** EtherType: Reverse Address Resolution Protocol */
    const uint16_t IEEE802      = 0x8100; /** EtherType: IEEE 802 */
    const uint16_t IPV6         = 0x86DD; /** EtherType: IPv6 */
    const uint16_t PPP          = 0x880B; /** EtherType: Point-to-Point Protocol */
    const uint16_t PTP          = 0x88F7; /** EtherType: Precision Time Protocol */
}

/* IPv4 */

namespace ipv4type {
    const uint8_t ICMP          = 0x01; /** IPv4 Type ICMP */
    const uint8_t TCP           = 0x06; /** IPv4 Type TCP */
    const uint8_t UDP           = 0x11; /** IPv4 Type UDP */
}

/* TCP */

#define TCP_STANDARD		20 	/** Standard header lenght (byte) */

/* ICMP */

namespace icmpv4type {
    const uint16_t ECHO_REPLY    = 0x0000; /** Echo reply (used to ping) */
    const uint16_t NETW_UNREACH  = 0x0300; /** Network unreachable */
    const uint16_t HOST_UNREACH  = 0x0301; /** Destination host unreachable */
    const uint16_t PROT_UNREACH  = 0x0302; /** Destination protocol unreachable */
    const uint16_t PORT_UNREACH  = 0x0303; /** Destination port unreachable */
    const uint16_t ECHO_REQUEST  = 0x0800; /** Echo request (used to ping) */
    const uint16_t ROUTER_SOLIC  = 0x1000; /** Router discovery/selection/solicitation */
    const uint16_t TTL_EXPIRED   = 0x1100; /** TTL expired in transit */
}

/* INCLUDE */

#include <string>
#include <boost/asio.hpp>
#include <stdint.h>
#include "macaddress.h"

namespace network {

    /** Class for managing packets */
    class packet {
    protected:

        uint64_t timeEpoch; /** Timestamp */
        uint32_t timeMillis; /** Millisecond from timestamp */
        uint32_t pkgLength; /** Packet length */
        std::string rawData; /** Raw packet recived from riddle */

        /** Legge n byte a partire dal byte voluto e li restituisce in stringa. */
        inline std::string getHexString(int string_cursor, int read_byte);

        /** Legge IPv4 dal byte voluto e restituisce in formato decimale. */
        inline std::string getDecimalIP(int string_cursor);

        /** Salva MAC address a partire da un punto (n� del byte) della stringa rawData */
        inline mac_address getMacAddress(int string_cursor);

    public:

        /** Overflow management */
        class Overflow {
        };

        /** Class constructor with delayed instantiation*/
        static packet* factory(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /** Class constructor with delayed instantiation, auto-split mode*/
        static packet* factory(std::string packetLine);

        /** Virtual destructor */
        virtual ~packet() {
        }

        /* GENERAL FUNCTIONS */

        /** Returns the packet length in bytes. */
        uint32_t getPacketLength();

        /** Returns packet epoch */
        uint64_t getEpoch();

        /** Returns milliseconds passed from epoch */
        uint32_t getMillis();

        /** true if this is an ARP packet. */
        inline bool isArp() {
            return ( this->getEtherType() == ethertype::ARP);
        }

        /** true if this is an IPv4 packet. */
        inline bool isIPv4() {
            return ( this->getEtherType() == ethertype::IPV4);
        }

        /** true if this is an IPv6 packet. */
        inline bool isIPv6() {
            return ( this->getEtherType() == ethertype::IPV6);
        }

        /* ETHERNET FUNCTIONS */

        /** returns the mac address of the sender. */
        mac_address getSenderMac();

        /** returns the mac address of the destination. */
        mac_address getTargetMac();

        /** returns ethertype */
        uint16_t getEtherType();

    };

    /** Class for managing ARP packets */
    class ARPpacket : public packet {
    public:

        /** final constructor. */
        ARPpacket(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /** returns OpCode */
        uint16_t getOpCode();

        /** returns the ip address of the sender. */
        boost::asio::ip::address getSenderIp();

        /** returns the ip address of the destination. */
        boost::asio::ip::address getTargetIp();

    };

    /** Class for managing IPv4 packets */
    class IPv4packet : public packet {
    public:

        /** Class constructor with delayed instantiation */
        static packet* factory(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

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
        inline bool isDF() {
            return ( this->getFlagsIP() & 64);
        }

        /** true if "More Fragments" flag is up */
        inline bool isMF() {
            return ( this->getFlagsIP() & 32);
        }

        /** true if the packet encapsulates a packet TCP. */
        inline bool isTCP() {
            return ( this->getProtocolType() == ipv4type::TCP);
        }

        /** true if the packet encapsulates a packet UDP. */
        inline bool isUDP() {
            return ( this->getProtocolType() == ipv4type::UDP);
        }

        /** true if the packet encapsulates a packet ICMP. */
        inline bool isICMP() {
            return ( this->getProtocolType() == ipv4type::ICMP);
        }

    };

    /** Class for managing TCPv4 packets */
    class TCPv4packet : public IPv4packet {
    public:

        /** public flag. use it as you want. */
        bool public_flag;

        /** final constructor. */
        TCPv4packet(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

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

        /** true if flag FIN is set. */
        inline bool isFIN() {
            return ( this->getFlagsTCP() & 1);
        }

        /** true if flag SYN is set. */
        inline bool isSYN() {
            return ( this->getFlagsTCP() & 2);
        }

        /** true if flag RST is set. */
        inline bool isRST() {
            return ( this->getFlagsTCP() & 4);
        }

        /** true if flag PSH is set. */
        inline bool isPSH() {
            return ( this->getFlagsTCP() & 8);
        }

        /** true if flag ACK is set. */
        inline bool isACK() {
            return ( this->getFlagsTCP() & 16);
        }

        /** true if flag URG is set. */
        inline bool isURG() {
            return ( this->getFlagsTCP() & 32);
        }

        /** true if flag ECE is set. */
        inline bool isECE() {
            return ( this->getFlagsTCP() & 64);
        }

        /** true if flag CWR is set. */
        inline bool isCWR() {
            return ( this->getFlagsTCP() & 128);
        }

        /** true if there are additional options. */
        inline bool isOption() {
            return ( this->getHeaderLength() > TCP_STANDARD);
        }

    };

    /** Class for managing UDPv4 packets */
    class UDPv4packet : public IPv4packet {
    public:

        /** final constructor. */
        UDPv4packet(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /** return the port of the sender. */
        uint16_t getSenderPort();

        /** return the port of the destination. */
        uint16_t getTargetPort();

    };

    /** Class for managing ICMPv4 packets */
    class ICMPv4packet : public IPv4packet {
    public:

        /** final constructor. */
        ICMPv4packet(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /** return message type. */
        uint16_t getMessageType();

        /** return message code. */
        uint16_t getMessageCode();

    };

    /** Class for managing unknown packets */
    class UnknownPacket : public packet {
    public:

        /** final constructor. */
        UnknownPacket(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

    };

}

#endif //PACKET_H
