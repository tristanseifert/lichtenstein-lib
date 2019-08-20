include(FindProtobuf)
find_package(Protobuf REQUIRED)

# define the library
add_library(lichtensteinProto STATIC version.c version.h WireMessage.h MessageSerializer.cpp MessageSerializer.h SerializationError.h GenericClientHandler.cpp GenericClientHandler.h ProtocolError.h)

# link against the protobuf library
target_link_libraries(lichtensteinProto ${PROTOBUF_LIBRARY})
include_directories(${PROTOBUF_INCLUDE_DIR})

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# link as well to LibreSSL (for generic client handler)
find_package(LibreSSL REQUIRED)
target_link_libraries(lichtensteinProto LibreSSL::TLS)


# pull in compiled protobufs
add_subdirectory(proto)
target_link_libraries(lichtensteinProto lichtensteinProtobufsShared lichtensteinProtobufsRt lichtensteinProtobufsClient lichtensteinProtobufsServer)