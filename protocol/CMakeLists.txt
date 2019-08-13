# define the library
add_library(libLichtensteinProto STATIC version.cpp version.h)

# pull in compiled protobufs
add_subdirectory(proto)
target_link_libraries(libLichtensteinProto lichtensteinProtobufs)