cmake_minimum_required(VERSION 2.6)
project(ProjectRiddle)

set(SYSCONF_INSTALL_DIR 
    "/etc"
    CACHE PATH "Path where to install configuration")


add_subdirectory(commons)	# Commons libraries.
add_subdirectory(libraries)	# Libraries for a single executable
add_subdirectory(config)	# Configuration example files

set(LIBRARIES_DIR libraries)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/commons/)

set(RIDDLE_SRCS Riddle.cpp)
set(CIGARETTE_SRCS ${LIBRARIES_DIR}/libCigarette.cpp ${LIBRARIES_DIR}/libCigarette.h Cigarette.cpp)
set(RANGING_SRCS ${LIBRARIES_DIR}/libRanging.h ${LIBRARIES_DIR}/libRanging.cpp Ranging.cpp)
set(PURSUER_SRCS ${LIBRARIES_DIR}/libPursuer.h ${LIBRARIES_DIR}/libPursuer.cpp Pursuer.cpp)
set(BREEDER_SRCS ${LIBRARIES_DIR}/libBreeder.h ${LIBRARIES_DIR}/libBreeder.cpp Breeder.cpp)

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

#Install binaries
install(TARGETS riddle DESTINATION sbin)
install(TARGETS breeder cigarette pursuer ranging DESTINATION bin)

#Generate packages
INCLUDE(InstallRequiredSystemLibraries)

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Riddle is a modular network sniffer")
SET(CPACK_PACKAGE_VENDOR "Andrea Bontempi")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "1")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
SET(CPACK_PACKAGE_CONTACT "Andrea Bontempi <andreabont@yahoo.it>")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Andrea Bontempi")
INCLUDE(CPack)
