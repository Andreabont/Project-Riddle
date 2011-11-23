
cmake_minimum_required(VERSION 2.6)
project(SNIFFER)

set(RIDDLE_SRCS libRiddle.cpp libRiddle.h Riddle.cpp)
add_executable(Riddle ${RIDDLE_SRCS})

set(HENDRIX_SRCS Hendrix.cpp)
add_executable(Hendrix ${HENDRIX_SRCS})

set(CIGARETTE_SRCS libCigarette.cpp libCigarette.h Cigarette.cpp)
add_executable(Cigarette ${CIGARETTE_SRCS})

set(BOOST_LIBS program_options system)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_library(LIBPCAP pcap)

target_link_libraries(Riddle ${Boost_LIBRARIES})
target_link_libraries(Riddle ${LIBPCAP})
target_link_libraries(Hendrix ${Boost_LIBRARIES})
target_link_libraries(Cigarette ${Boost_LIBRARIES})
