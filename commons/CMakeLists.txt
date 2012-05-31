project (commons)

add_library (libNetwork STATIC libAddress.h libAddress.cpp libPacket.h libPacket.cpp)
add_library (libDump STATIC libDump.h libDump.cpp)

target_link_libraries (libNetwork)
target_link_libraries (libDump)