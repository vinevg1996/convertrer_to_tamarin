cmake_minimum_required(VERSION 3.5)

set (CMAKE_CXX_STANDARD 11)

add_library(agent src/agent.cpp src/agent.h src/rule.cpp src/rule.h)

add_executable(main_file src/main_file.cpp)

target_link_libraries(main_file agent)
