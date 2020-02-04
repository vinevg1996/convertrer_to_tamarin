cmake_minimum_required(VERSION 3.5)

set (CMAKE_CXX_STANDARD 11)

add_library(protocol src/protocol.cpp src/protocol.h)

add_executable(main src/main.cpp)

target_link_libraries(main protocol)
