cmake_minimum_required(VERSION 2.6)
project(ProjectRiddle)

# Project settings
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x") 

set(SYSCONF_INSTALL_DIR 
    "/etc"
    CACHE PATH "Path where to install configuration")

# Enable test
enable_testing()

# Projects includes
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/commons/)

# Project modules (Comment for disable, pay attention to dependencies)
add_subdirectory(commons)	# Commons libraries
add_subdirectory(config)	# Configuration files
add_subdirectory(riddle)	# Riddles files
add_subdirectory(breeder)	# Breeder files
add_subdirectory(pursuer)	# Pursuer files
add_subdirectory(cigarette)	# Cigarette files
add_subdirectory(ranging)	# Ranging files
add_subdirectory(test)          # Test files

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