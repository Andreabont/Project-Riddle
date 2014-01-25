cmake_minimum_required(VERSION 2.6)
project (breeder)

set(BREEDER_SRCS 
${PROJECT_SOURCE_DIR}/tools.h
${PROJECT_SOURCE_DIR}/tools.cpp
${PROJECT_SOURCE_DIR}/main.cpp
)

add_executable(breeder ${BREEDER_SRCS})

# Include libraries
set(BOOST_LIBS program_options system regex thread)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_package(Threads)
include_directories("${PROJECT_SOURCE_DIR}/../commons/")

# Build breeder
target_link_libraries(breeder ${Boost_LIBRARIES})
target_link_libraries(breeder ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(breeder network)
target_link_libraries(breeder dump)

# Install breeder
install(TARGETS breeder DESTINATION bin)
