cmake_minimum_required(VERSION 2.6)
project (riddle)

set(RIDDLE_SRCS 
${PROJECT_SOURCE_DIR}/main.cpp
)

add_executable(riddle ${RIDDLE_SRCS})

# Include libraries
find_library(LIBPCAP pcap)
set(BOOST_LIBS program_options system regex thread)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
include_directories("${PROJECT_SOURCE_DIR}/../commons/")

# Build riddle
target_link_libraries(riddle ${Boost_LIBRARIES})
target_link_libraries(riddle ${LIBPCAP})
target_link_libraries(riddle dump)

# Install riddle
install(TARGETS riddle DESTINATION sbin)
