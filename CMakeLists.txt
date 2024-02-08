cmake_minimum_required(VERSION 3.28)
project(NetworkUtil)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

link_libraries(crypto)

add_executable(netutil main.cpp)
