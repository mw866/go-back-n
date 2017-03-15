cmake_minimum_required(VERSION 3.6)
project(go_back_n)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        gbn.c
        gbn.h
        Makefile
        receiver.c
        sender.c)

add_executable(go_back_n ${SOURCE_FILES})