cmake_minimum_required(VERSION 2.6)
project (cigarette)

set(CIGARETTE_SRCS 
${PROJECT_SOURCE_DIR}/tools.h
${PROJECT_SOURCE_DIR}/tools.cpp
${PROJECT_SOURCE_DIR}/main.cpp
)

add_executable(cigarette ${CIGARETTE_SRCS})

# Include libraries
set(BOOST_LIBS program_options system regex thread)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_package(Threads)
include_directories("${PROJECT_SOURCE_DIR}/../commons/")

# Build cigarette
target_link_libraries(cigarette ${Boost_LIBRARIES})
target_link_libraries(cigarette ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(cigarette network)
target_link_libraries(cigarette dump)

# Install cigarette
install(TARGETS cigarette DESTINATION bin)
