cmake_minimum_required(VERSION 2.6)
project(ProjectRiddle)

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x") 

set(SYSCONF_INSTALL_DIR 
    "/etc"
    CACHE PATH "Path where to install configuration")

add_subdirectory(commons)	# Commons libraries
add_subdirectory(config)	# Configuration files

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/commons/)

set(RIDDLE_SRCS riddle/main.cpp)
set(CIGARETTE_SRCS cigarette/tools.cpp cigarette/tools.h cigarette/main.cpp)
set(RANGING_SRCS ranging/tools.h ranging/tools.cpp ranging/main.cpp)
set(PURSUER_SRCS pursuer/tools.h pursuer/tools.cpp pursuer/main.cpp)
set(BREEDER_SRCS breeder/tools.h breeder/tools.cpp breeder/main.cpp)

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

# Build riddle
target_link_libraries(riddle ${Boost_LIBRARIES})
target_link_libraries(riddle ${LIBPCAP})
target_link_libraries(riddle dump)

# Build cigarette
target_link_libraries(cigarette ${Boost_LIBRARIES})
target_link_libraries(cigarette ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(cigarette network)
target_link_libraries(cigarette dump)

# Build ranging
target_link_libraries(ranging ${Boost_LIBRARIES})
target_link_libraries(ranging ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(ranging ${CURSES_LIBRARY})
target_link_libraries(ranging network)

# Build pursuer
target_link_libraries(pursuer ${Boost_LIBRARIES})
target_link_libraries(pursuer ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(pursuer network)
target_link_libraries(pursuer dump)

# Build breeder
target_link_libraries(breeder ${Boost_LIBRARIES})
target_link_libraries(breeder ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(breeder network)
target_link_libraries(breeder dump)

# Install binaries
install(TARGETS riddle DESTINATION sbin)
install(TARGETS breeder cigarette pursuer ranging DESTINATION bin)

# Generate packages
INCLUDE(InstallRequiredSystemLibraries)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Riddle is a modular network sniffer")
set(CPACK_PACKAGE_VENDOR "Andrea Bontempi")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "2")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
set(CPACK_PACKAGE_CONTACT "Andrea Bontempi <andreabont@yahoo.it>")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Andrea Bontempi")
INCLUDE(CPack)
