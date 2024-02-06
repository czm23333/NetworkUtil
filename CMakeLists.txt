cmake_minimum_required(VERSION 3.28)
project(NetworkUtil)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

add_executable(netutil main.cpp)
