cmake_minimum_required(VERSION 2.6)
project(SNIFFER)

add_subdirectory(commons)
add_subdirectory(libraries)

set(LIBRARIES_DIR libraries)

set(RIDDLE_SRCS ${LIBRARIES_DIR}/libRiddle.cpp ${LIBRARIES_DIR}/libRiddle.h Riddle.cpp)
set(CIGARETTE_SRCS ${LIBRARIES_DIR}/libCigarette.cpp ${LIBRARIES_DIR}/libCigarette.h Cigarette.cpp)
set(RANGING_SRCS ${LIBRARIES_DIR}/libRanging.h ${LIBRARIES_DIR}/libRanging.cpp Ranging.cpp)
set(PURSUER_SRCS ${LIBRARIES_DIR}/libPursuer.h ${LIBRARIES_DIR}/libPursuer.cpp Pursuer.cpp)
set(BREEDER_SRCS Breeder.cpp)

add_executable(ranging ${RANGING_SRCS})
add_executable(cigarette ${CIGARETTE_SRCS})
add_executable(riddle ${RIDDLE_SRCS})
add_executable(pursuer ${PURSUER_SRCS})
add_executable(breeder ${BREEDER_SRCS})

set(BOOST_LIBS program_options system regex thread)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)

find_library(LIBPCAP pcap)

find_package (Threads)

SET(CURSES_NEED_NCURSES TRUE)
find_package(Curses)

target_link_libraries(riddle ${Boost_LIBRARIES})
target_link_libraries(riddle ${LIBPCAP})
target_link_libraries(riddle libDump)

target_link_libraries(cigarette ${Boost_LIBRARIES})
target_link_libraries(cigarette ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(cigarette libNetwork)
target_link_libraries(cigarette libDump)

target_link_libraries(ranging ${Boost_LIBRARIES})
target_link_libraries(ranging ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(ranging ${CURSES_LIBRARY})
target_link_libraries(ranging libNetwork)

target_link_libraries(pursuer ${Boost_LIBRARIES})
target_link_libraries(pursuer ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(pursuer libNetwork)
target_link_libraries(pursuer libDump)

target_link_libraries(breeder ${Boost_LIBRARIES})
target_link_libraries(breeder ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(breeder libNetwork)
target_link_libraries(breeder libDump)
target_link_libraries(breeder libMatch)