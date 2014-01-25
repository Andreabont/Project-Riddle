cmake_minimum_required(VERSION 2.6)
project (ranging)

set(RANGING_SRCS 
${PROJECT_SOURCE_DIR}/thread.h
${PROJECT_SOURCE_DIR}/thread.cpp
${PROJECT_SOURCE_DIR}/thread_printer.cpp
${PROJECT_SOURCE_DIR}/thread_scribe.cpp
${PROJECT_SOURCE_DIR}/tools.h
${PROJECT_SOURCE_DIR}/tools.cpp
${PROJECT_SOURCE_DIR}/main.cpp
)

add_executable(ranging ${RANGING_SRCS})

# Include libraries
set(CURSES_NEED_NCURSES TRUE)
find_package(Curses)
set(BOOST_LIBS program_options system regex thread)
find_package(Boost COMPONENTS ${BOOST_LIBS} REQUIRED)
find_package(Threads)
include_directories("${PROJECT_SOURCE_DIR}/../commons/")

# Build ranging
target_link_libraries(ranging ${Boost_LIBRARIES})
target_link_libraries(ranging ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(ranging ${CURSES_LIBRARY})
target_link_libraries(ranging network)

# Install ranging
install(TARGETS ranging DESTINATION bin)
