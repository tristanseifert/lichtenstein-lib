include(FindProtobuf)
find_package(Protobuf REQUIRED)

# define the library
add_library(lichtensteinProto STATIC version.cpp version.h)

# link against the protobuf library
target_link_libraries(lichtensteinProto ${PROTOBUF_LIBRARY})

# pull in compiled protobufs
add_subdirectory(proto)
target_link_libraries(lichtensteinProto lichtensteinProtobufsShared lichtensteinProtobufsRt)