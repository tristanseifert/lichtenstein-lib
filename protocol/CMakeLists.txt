# define the library
add_library(lichtensteinProto STATIC version.cpp version.h)

# pull in compiled protobufs
add_subdirectory(proto)
target_link_libraries(lichtensteinProto PRIVATE lichtensteinProtobufs)