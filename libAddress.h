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

#ifndef LIBADDRESS_H
#define LIBADDRESS_H

#include <string>

class mac_address
{
  public:
  void set(std::string, int);
  std::string print();
 
  private:
  short int byte[6];
};

class ipv4_address
{
  public:
  void set(std::string, int);
  std::string print();
  
  private:
  short int byte[4];
};

class ipv6_address
{
  public:
  void set(std::string, int);
  std::string print();
  
  private:
  short int byte[8];
};

#endif //LIBADDRESS_H