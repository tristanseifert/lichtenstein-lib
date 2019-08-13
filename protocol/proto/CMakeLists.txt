# pull in protobuf lib
include(FindProtobuf)
find_package(Protobuf REQUIRED)

# specify include directories and generate C++
include_directories(${PROTOBUF_INCLUDE_DIR})
protobuf_generate_cpp(PROTO_SRC PROTO_HEADER message.proto)

# specify it as a library
add_library(lichtensteinProtobufs ${PROTO_HEADER} ${PROTO_SRC})