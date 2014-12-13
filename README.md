Build and install
=================

Installing the dependencies
---------------------------
- cmake
- libboost
- libpcap

Compile!
--------
```sh
git clone https://github.com/Andreabont/Project-Riddle.git
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DSYSCONF_INSTALL_DIR=/etc
make
make test
make install
```

Example
=======

Get ARP packets from eth0
-------------------------
```sh
sudo ./riddle --iface eth0 --filter arp --dump
```

Show packets from wlan0
-----------------------
```sh
sudo ./riddle --iface wlan0 | ./cigarette
```

Show computers in the network (MAC and IP address)
--------------------------------------------------
```sh
sudo ./riddle --iface wlan0 | ./ranging
```
