/**
 * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * - * -
 *
 * Name        :  Project Riddle
 * Author      :  Andrea Bontempi
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

#include <string>
#include <memory>
#include <cstdint>
#include <boost/asio.hpp>
#include "macaddress.h"

/**
 * Position of the header from the beginning of the packet.
 */
namespace offset {
    const uint8_t ARP = 14; /** ARP Offset */
    const uint8_t IPV4 = 14; /** IPv4 Offset */
    const uint8_t TCP = 34; /** TCP Offset */
    const uint8_t UDP = 34; /** UDP Offset */
    const uint8_t ICMPV4 = 34; /** ICMPv4 Offsets */
}

/**
 * Translation of "EtherType" codes.
 */
namespace ethertype {
    const uint16_t V2_CODE = 0x0600; /** EtherType: Below this value means "length" */
    const uint16_t IPV4 = 0x0800; /** EtherType: IPv4 */
    const uint16_t ARP = 0x0806; /** EtherType: Address Resolution Protocol */
    const uint16_t WOL = 0x0842; /** EtherType: Wake-On-Lan */
    const uint16_t RARP = 0x8035; /** EtherType: Reverse Address Resolution Protocol */
    const uint16_t IEEE802 = 0x8100; /** EtherType: IEEE 802 */
    const uint16_t IPV6 = 0x86DD; /** EtherType: IPv6 */
    const uint16_t PPP = 0x880B; /** EtherType: Point-to-Point Protocol */
    const uint16_t PTP = 0x88F7; /** EtherType: Precision Time Protocol */
}

/**
 * Translation of "IPv4" codes.
 */
namespace ipv4type {
    const uint8_t ICMP = 0x01; /** IPv4 Type ICMP */
    const uint8_t TCP = 0x06; /** IPv4 Type TCP */
    const uint8_t UDP = 0x11; /** IPv4 Type UDP */
}

/* TCP */

#define TCP_STANDARD		20 	/** Standard header lenght (byte) */

/**
 * Translation of "ICMP" codes.
 */
namespace icmpv4type {
    const uint16_t ECHO_REPLY = 0x0000; /** Echo reply (used to ping) */
    const uint16_t NETW_UNREACH = 0x0300; /** Network unreachable */
    const uint16_t HOST_UNREACH = 0x0301; /** Destination host unreachable */
    const uint16_t PROT_UNREACH = 0x0302; /** Destination protocol unreachable */
    const uint16_t PORT_UNREACH = 0x0303; /** Destination port unreachable */
    const uint16_t ECHO_REQUEST = 0x0800; /** Echo request (used to ping) */
    const uint16_t ROUTER_SOLIC = 0x1000; /** Router discovery/selection/solicitation */
    const uint16_t TTL_EXPIRED = 0x1100; /** TTL expired in transit */
}

namespace network {

    /** Class for managing packets */
    class packet {
    public:

        /** Overflow management */
        class Overflow : public std::exception {
        public:

            const char* what() const throw () {
                const char* mex = "Overflow";
                return mex;
            }

        };

        /**
         * Class constructor with delayed instantiation.
         * \param timeEpoch_i is the date and time of capture expressed in POSIX time.
         * \param timeMillis_i are the milliseconds passed since Epoch.
         * \param rawData_i is the raw packet in hexadecimal format.
         * \return an instance of "packet".
         */
        static std::shared_ptr<network::packet> factory(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /**
         * Class constructor with delayed instantiation, auto-split mode.
         * \param packetLine is the packet in "Riddle" format.
         * \return an instance of "packet".
         */
        static std::shared_ptr<network::packet> factory(std::string packetLine);

        /** Virtual destructor */
        virtual ~packet() {
        }

        /* GENERAL FUNCTIONS */

        /**
         * \return the packet length in bytes.
         */
        uint32_t getPacketLength();

        /**
         * \return packet Epoch.
         */
        uint64_t getEpoch();

        /**
         * \return milliseconds passed since Epoch.
         */
        uint32_t getMillis();

        /**
         * \return true if this is an ARP packet.
         */
        inline bool isArp() {
            return ( this->getEtherType() == ethertype::ARP);
        }

        /**
         * \return true if this is an IPv4 packet.
         */
        inline bool isIPv4() {
            return ( this->getEtherType() == ethertype::IPV4);
        }

        /**
         * \return true if this is an IPv6 packet.
         */
        inline bool isIPv6() {
            return ( this->getEtherType() == ethertype::IPV6);
        }

        /* ETHERNET FUNCTIONS */

        /**
         * \return the sender mac_address.
         */
        mac_address getSenderMac();

        /**
         * \return the destination mac_address.
         */
        mac_address getTargetMac();

        /**
         * \return the ethertype code.
         */
        uint16_t getEtherType();

    protected:

        uint64_t timeEpoch; /** Timestamp */
        uint32_t timeMillis; /** Millisecond from timestamp */
        uint32_t pkgLength; /** Packet length */
        std::string rawData; /** Raw packet recived from riddle */

        /**
         * Extracts in hexadecimal format a portion of the captured packet.
         * \param string_cursor indicates where to start to extract the data.
         * \param read_byte indicates how much data are extracted.
         * \return a string containing the extracted data in hexadecimal format.
         */
        std::string getHexString(int string_cursor, int read_byte) throw (Overflow);

        /**
         * Extracts an IP address in the specified location and puts it in a human-readable format.
         * \param string_cursor indicates where to start to extract the data.
         * \return a string containing the IP address in dot-decimal notation.
         */
        std::string getDecimalIP(int string_cursor) throw (Overflow);

        /**
         * Extracts an MAC address in the specified location and puts it in the object "mac_address".
         * \param string_cursor indicates where to start to extract the data.
         * \return a mac_address object.
         */
        mac_address getMacAddress(int string_cursor) throw (Overflow);

        uint32_t getLength();

    };

    /** Class for managing ARP packets */
    class ARPpacket : public packet {
    public:

        /** final constructor. */
        ARPpacket(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /**
         * \return OpCode.
         */
        uint16_t getOpCode();

        /**
         * \return the sender IP address.
         */
        boost::asio::ip::address getSenderIp();

        /**
         * \return the destination IP address.
         */
        boost::asio::ip::address getTargetIp();

    };

    /** Class for managing IPv4 packets */
    class IPv4packet : public packet {
    public:

        /** Class constructor with delayed instantiation */
        static packet* factory(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /**
         * \return the sender IP address.
         */
        boost::asio::ip::address getSenderIp();

        /**
         * \return the destination IP address.
         */
        boost::asio::ip::address getTargetIp();

        /**
         * \return identity.
         */
        uint16_t getIdentity();

        /**
         * \return Time To Live.
         */
        uint16_t getTTL();

        /**
         * \return protocol type.
         */
        uint16_t getProtocolType();

        /**
         * \return checksum.
         */
        uint16_t getIPChecksum();

        /**
         * \return true if checksum is correct.
         */
        bool verifyIPChecksum();

        /**
         * \return raw flags.
         */
        int getFlagsIP();

        /**
         * \return true if "Don't Fragment" flag is up.
         */
        inline bool isDF() {
            return ( this->getFlagsIP() & 64);
        }

        /**
         * \return true if "More Fragments" flag is up.
         */
        inline bool isMF() {
            return ( this->getFlagsIP() & 32);
        }

        /**
         * \return true if the packet encapsulates a packet TCP.
         */
        inline bool isTCP() {
            return ( this->getProtocolType() == ipv4type::TCP);
        }

        /**
         * \return true if the packet encapsulates a packet UDP.
         */
        inline bool isUDP() {
            return ( this->getProtocolType() == ipv4type::UDP);
        }

        /**
         * \return true if the packet encapsulates a packet ICMP.
         */
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

        /**
         * \return the port of the sender.
         */
        uint16_t getSenderPort();

        /**
         * \return the port of the destination.
         */
        uint16_t getTargetPort();

        /**
         * \return sequence number.
         */
        uint32_t getSequenceNumber();

        /**
         * \return acknowledgment number.
         */
        uint32_t getAcknowledgmentNumber();

        /**
         * \return expected acknowledgment number.
         */
        uint32_t getExpectedAcknowledgmentNumber();

        /**
         * \return the TCP header size in bytes.
         */
        unsigned int getHeaderLength();

        /**
         * \return the TCP payload size in bytes.
         */
        unsigned int getPayloadLength();

        /**
         * \return raw flags.
         */
        int getFlagsTCP();

        /**
         * \return size of the receive window in bytes.
         */
        unsigned int getWindowSize();

        /**
         * \return checksum.
         */
        unsigned int getTCPChecksum();

        /**
         * \return the urgent pointer.
         */
        unsigned int getUrgentPointer();

        /**
         * \return raw TCP option.
         */
        std::string getOptionRaw();

        /**
         * \return TCP option in a std::map.
         */
        std::map<int, std::string> getOptionMap();

        /**
         * \return packet payload.
         */
        std::string getPayLoad();

        /**
         * \return true if flag FIN is set.
         */
        inline bool isFIN() {
            return ( this->getFlagsTCP() & 1);
        }

        /**
         * \return true if flag SYN is set.
         */
        inline bool isSYN() {
            return ( this->getFlagsTCP() & 2);
        }

        /**
         * \return true if flag RST is set.
         */
        inline bool isRST() {
            return ( this->getFlagsTCP() & 4);
        }

        /**
         * \return true if flag PSH is set.
         */
        inline bool isPSH() {
            return ( this->getFlagsTCP() & 8);
        }

        /**
         * \return true if flag ACK is set.
         */
        inline bool isACK() {
            return ( this->getFlagsTCP() & 16);
        }

        /**
         * \return true if flag URG is set.
         */
        inline bool isURG() {
            return ( this->getFlagsTCP() & 32);
        }

        /**
         * \return true if flag ECE is set.
         */
        inline bool isECE() {
            return ( this->getFlagsTCP() & 64);
        }

        /**
         * \return true if flag CWR is set.
         */
        inline bool isCWR() {
            return ( this->getFlagsTCP() & 128);
        }

        /**
         * \return true if there are additional options.
         */
        inline bool isOption() {
            return ( this->getHeaderLength() > TCP_STANDARD);
        }

    };

    /** Class for managing UDPv4 packets */
    class UDPv4packet : public IPv4packet {
    public:

        /** final constructor. */
        UDPv4packet(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /**
         * \return the port of the sender.
         */
        uint16_t getSenderPort();

        /**
         * \return the port of the destination.
         */
        uint16_t getTargetPort();

        /**
         * \return packet payload.
         */
        std::string getPayLoad();

    };

    /** Class for managing ICMPv4 packets */
    class ICMPv4packet : public IPv4packet {
    public:

        /** final constructor. */
        ICMPv4packet(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

        /**
         * \return message type + code.
         */
        uint16_t getMessageType();

    };

    /** Class for managing unknown packets */
    class UnknownPacket : public packet {
    public:

        /** final constructor. */
        UnknownPacket(uint64_t timeEpoch_i, uint32_t timeMillis_i, std::string rawData_i);

    };

}

#endif //PACKET_H
