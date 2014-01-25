cmake_minimum_required(VERSION 2.6)
project (pursuer)

set(PURSUER_SRCS 
${PROJECT_SOURCE_DIR}/tools.h
${PROJECT_SOURCE_DIR}/tools.cpp
${PROJECT_SOURCE_DIR}/main.cpp
)

add_executable(pursuer ${PURSUER_SRCS})

# Include libraries
set(BOOST_LIBS program_options system regex thread)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_package(Threads)
include_directories("${PROJECT_SOURCE_DIR}/../commons/")

# Build pursuer
target_link_libraries(pursuer ${Boost_LIBRARIES})
target_link_libraries(pursuer ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(pursuer network)
target_link_libraries(pursuer dump)


# Install pursuer
install(TARGETS pursuer DESTINATION bin)
