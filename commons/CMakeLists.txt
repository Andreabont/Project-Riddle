project (commons)

add_library (libNetwork STATIC classMacAddress.h classMacAddress.cpp classPacket.h classPacket.cpp classFlow.h classFlow.cpp)
add_library (libDump STATIC libDump.h libDump.cpp)
add_library (libMatch STATIC classFlowMatch.h classFlowMatch.cpp)

target_link_libraries (libNetwork)
target_link_libraries (libDump)
target_link_libraries (libMatch)