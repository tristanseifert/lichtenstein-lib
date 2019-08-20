include(FindProtobuf)
find_package(Protobuf REQUIRED)

# define the library
add_library(lichtensteinProto STATIC version.c version.h WireMessage.h MessageSerializer.cpp MessageSerializer.h SerializationError.h GenericClientHandler.cpp GenericClientHandler.h ProtocolError.h)

# link against the protobuf library
target_link_libraries(lichtensteinProto ${PROTOBUF_LIBRARY})
include_directories(${PROTOBUF_INCLUDE_DIR})

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# link with LibreSSL
if (APPLE)
    # a kind of nasty hack for macOS, otherwise it will link with system OpenSSL :(
    include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
    target_link_libraries(lichtensteinProto /usr/local/opt/libressl/lib/libcrypto.dylib /usr/local/opt/libressl/lib/libssl.dylib /usr/local/opt/libressl/lib/libtls.dylib)
else ()
    target_link_libraries(lichtensteinProto LibreSSL::TLS)
endif ()


# pull in compiled protobufs
add_subdirectory(proto)
target_link_libraries(lichtensteinProto lichtensteinProtobufsShared lichtensteinProtobufsRt lichtensteinProtobufsClient lichtensteinProtobufsServer)