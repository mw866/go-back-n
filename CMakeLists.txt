cmake_minimum_required(VERSION 3.6)
project(go_back_n)

set(CMAKE_CXX_STANDARD 11)

add_executable(sender gbn.c gbn.h sender.c)
add_executable(receiver gbn.c gbn.h receiver.c)