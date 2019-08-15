cmake_minimum_required(VERSION 3.14)
project(liblichtenstein)

#[[
# Shared C++ options
#]]
set(CMAKE_CXX_STANDARD 17)



#[[
# libLichtensteinProto - Static protocol library
#]]
add_subdirectory(protocol)

#[[
# libLichtenteinClient - Dynamic client protocol handler
#]]
add_library(lichtensteinClient SHARED library.cpp library.h)
target_link_libraries(lichtensteinClient lichtensteinProto)