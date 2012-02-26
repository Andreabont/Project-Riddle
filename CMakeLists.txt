set(CMAKE_BUILD_TYPE Release)

cmake_minimum_required(VERSION 2.6)
project(SNIFFER)

set(RIDDLE_SRCS libRiddle.cpp libRiddle.h Riddle.cpp)
add_executable(riddle ${RIDDLE_SRCS})

set(CIGARETTE_SRCS libAddress.cpp libAddress.h libPacket.cpp libPacket.h libCigarette.cpp libCigarette.h Cigarette.cpp)
add_executable(cigarette ${CIGARETTE_SRCS})

set(BOOST_LIBS program_options system)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_library(LIBPCAP pcap)

target_link_libraries(riddle ${Boost_LIBRARIES})
target_link_libraries(riddle ${LIBPCAP})
target_link_libraries(hendrix ${Boost_LIBRARIES})
target_link_libraries(cigarette ${Boost_LIBRARIES})
