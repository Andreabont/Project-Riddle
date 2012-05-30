project (commons)

add_library (libAddress STATIC libAddress.h libAddress.cpp)
add_library (libPacket STATIC libPacket.h libPacket.cpp)

target_link_libraries (libAddress)
target_link_libraries (libPacket)