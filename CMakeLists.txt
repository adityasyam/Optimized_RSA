cmake_minimum_required(VERSION 3.10)
project(bignum)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(bignum 
  bignum.cpp
  main.cpp
)

target_include_directories(bignum PUBLIC ${CMAKE_SOURCE_DIR})

target_compile_options(bignum PUBLIC -O3)
