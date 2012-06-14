project (commons)

add_library (libNetwork STATIC classMacAddress.h classMacAddress.cpp classPacket.h classPacket.cpp classFlow.h classFlow.cpp)
add_library (libDump STATIC libDump.h libDump.cpp)

target_link_libraries (libNetwork)
target_link_libraries (libDump)