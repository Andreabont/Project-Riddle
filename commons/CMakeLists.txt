project (commons)

add_library (network STATIC macaddress.h macaddress.cpp packet.h packet.cpp tcpflow.h tcpflow.cpp)
add_library (dump STATIC dumptools.h dumptools.cpp)

target_link_libraries (network)
target_link_libraries (dump)
