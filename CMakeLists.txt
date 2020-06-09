cmake_minimum_required(VERSION 3.16)
project(version)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_PREFIX "")

add_library(version SHARED hook.cpp library.def proxy.h jni.h jni_x86.h parser.h dump.h)
link_libraries(ws2_32)

add_subdirectory(mhook)
target_compile_options(mhook PUBLIC -w)
target_link_libraries(version mhook)