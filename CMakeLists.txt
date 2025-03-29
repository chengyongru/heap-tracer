cmake_minimum_required(VERSION 3.22)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
add_compile_options("-g")
project(heap-tracer)

add_library(malloc SHARED hook.c)