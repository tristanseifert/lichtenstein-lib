include(FindProtobuf)
find_package(Protobuf REQUIRED)

# define the library
add_library(lichtensteinProto STATIC version.c version.h WireMessage.h MessageSerializer.cpp MessageSerializer.h SerializationError.h)

# link against the protobuf library
target_link_libraries(lichtensteinProto ${PROTOBUF_LIBRARY})
include_directories(${PROTOBUF_INCLUDE_DIR})

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# pull in compiled protobufs
add_subdirectory(proto)
target_link_libraries(lichtensteinProto lichtensteinProtobufsShared lichtensteinProtobufsRt lichtensteinProtobufsClient lichtensteinProtobufsServer)