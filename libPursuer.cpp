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
#include <string>
#include <ios>
#include <boost/asio.hpp>
#include <list>
#include "libPacket.h"
#include "libAddress.h"
#include "libPursuer.h"

stream::stream(TCPv4packet *SYN)
{
    timeEpoch = SYN->getEpoch();
    timeMillis = SYN->getMillis();
    first_mac = SYN->getSenderMac();
    second_mac = SYN->getTargetMac();
    first_ip = SYN->getSenderIp();
    second_ip = SYN->getTargetIp();
    first_port = SYN->getSenderPort();
    second_port = SYN->getTargetPort();
    first_sn = SYN->getSequenceNumber();
    second_sn = 0;
    flagFirstFIN = false;
    flagSecondFIN = false;
    
    delete SYN;

    return;
}

bool stream::streamSynAck(TCPv4packet *SYN)
{

    if(first_sn + 1 == SYN->getAcknowledgmentNumber() && SYN->isACK() && SYN->isSYN())
    {
        second_sn = SYN->getSequenceNumber();
        return true;
    }

    delete SYN;

    return false;

}


bool stream::addPacket(TCPv4packet *newPacket)
{

  using namespace std;
  
    if(!newPacket->isSYN())
    {

        if(newPacket->getSenderPort() == first_port)
        {
            // Siamo nel first_buffer
            first_buffer.push_back(newPacket);	    
            for (list<TCPv4packet*>::iterator it = second_buffer.begin(); it != second_buffer.end(); it++)
            {
                if( (*it)->getSequenceNumber() + 1 == newPacket->getAcknowledgmentNumber() )
                {
                    (*it)->public_flag == true;
                    break;
                }
            }
            return true;
        }
        else if (newPacket->getSenderPort() == second_port)
        {
            second_buffer.push_back(newPacket);
            for (list<TCPv4packet*>::iterator it = first_buffer.begin(); it != first_buffer.end(); it++)
            {
                if( (*it)->getSequenceNumber() + 1 == newPacket->getAcknowledgmentNumber() )
                {
                    (*it)->public_flag == true;
                    break;
                }
            }
            return true;
        } else return false;

    }

    return false;

}

void stream::flushFirstBuffer()
{
    bool isFound = false;

    do
    {

        for (std::list<TCPv4packet*>::iterator it = first_buffer.begin(); it != first_buffer.end(); it++)
        {
std::cerr << "Trovato pacchetto nel primo buffer" << std::endl;
            if(first_sn + 1 == (*it)->getSequenceNumber() && (*it)->public_flag)
            {
                first_flow += (*it)->getPayLoad();
		std::cerr << "Nel buffer: " << (*it)->getPayLoad() << std::endl;
                first_sn++; // FIXME se si azzera?
                first_buffer.remove(*it);
                delete &(*it);
                isFound == true;
                break;
            }
            else
            {
                isFound == false;
            }
        }

    } while (isFound);

}

void stream::flushSecondBuffer()
{
    bool isFound = false;

    do
    {

        for (std::list<TCPv4packet*>::iterator it = second_buffer.begin(); it != second_buffer.end(); it++)
        {
	  std::cerr << "Trovato pacchetto nel secondo buffer" << std::endl;

            if(second_sn + 1 == (*it)->getSequenceNumber() && (*it)->public_flag)
            {
                second_flow += (*it)->getPayLoad();
                second_sn++; // FIXME se si azzera?
                second_buffer.remove(*it);
                delete &(*it);
                isFound == true;
                break;
            }
            else
            {
                isFound == false;
            }
        }

    } while (isFound);
}

std::string stream::exportFlow()
{
    return first_flow + second_flow; // TODO
}


long int stream::getTimeEpoch()
{
    return timeEpoch;
}

int stream::getTimeMillis()
{
    return timeMillis;
}

mac_address stream::getFirstMacAddress()
{
    return first_mac;
}

mac_address stream::getSecondMacAddress()
{
    return second_mac;
}

boost::asio::ip::address stream::getFirstIpAddress()
{
    return first_ip;
}

boost::asio::ip::address stream::getSecondIpAddress()
{
    return second_ip;
}

unsigned int stream::getFirstPort()
{
    return first_port;
}

unsigned int stream::getSecondPort()
{
    return second_port;
}

unsigned int stream::getFirstSN()
{
    return first_sn;
}

unsigned int stream::getSecondSN()
{
    return second_sn;
}

bool stream::isFIN()
{
    return flagFirstFIN && flagSecondFIN;
}
