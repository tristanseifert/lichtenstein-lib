cmake_minimum_required(VERSION 3.14)
project(liblichtenstein)

#[[
# Set up some search paths
#]]
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake;${CMAKE_MODULE_PATH}")

#[[
# Shared C++ options
#]]
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_VERBOSE_MAKEFILE ON)

# enable address and ub sanitizer
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -fsanitize=undefined,address,integer")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=undefined,address,integer")

#[[
# libLichtensteinProto - Static protocol library
#]]
add_subdirectory(protocol)

#[[
# libLichtensteinIo - Static library with IO helpers
#]]
add_subdirectory(io)

#[[
# libLichtenteinClient - Dynamic client protocol handler
#]]
add_subdirectory(client)


#[[
# libLichtensteinTests - testing for library (with Catch2)
#]]
add_subdirectory(tests)