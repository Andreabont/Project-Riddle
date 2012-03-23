cmake_minimum_required(VERSION 2.6)
project(SNIFFER)

set(RIDDLE_SRCS libRiddle.cpp libRiddle.h Riddle.cpp)
add_executable(riddle ${RIDDLE_SRCS})

set(CIGARETTE_SRCS libAddress.cpp libAddress.h libPacket.cpp libPacket.h libCigarette.cpp libCigarette.h Cigarette.cpp)
add_executable(cigarette ${CIGARETTE_SRCS})

set(RANGING_SRCS libAddress.h libAddress.cpp libPacket.h libPacket.cpp libRanging.h libRanging.cpp Ranging.cpp)
add_executable(ranging ${RANGING_SRCS})

set(PURSUER_SRCS libAddress.h libAddress.cpp libPacket.h libPacket.cpp libPursuer.h libPursuer.cpp Pursuer.cpp)
add_executable(pursuer ${PURSUER_SRCS})

set(BOOST_LIBS program_options system)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_library(LIBPCAP pcap)
find_package (Threads)
SET(CURSES_NEED_NCURSES TRUE)
find_package(Curses)

target_link_libraries(riddle ${Boost_LIBRARIES})
target_link_libraries(riddle ${LIBPCAP})
target_link_libraries(cigarette ${Boost_LIBRARIES})
target_link_libraries(cigarette ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(ranging ${Boost_LIBRARIES})
target_link_libraries(ranging ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(ranging ${CURSES_LIBRARY})
target_link_libraries(pursuer ${Boost_LIBRARIES})
target_link_libraries(pursuer ${CMAKE_THREAD_LIBS_INIT})
