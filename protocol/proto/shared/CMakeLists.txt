# pull in protobuf lib
include(FindProtobuf)
find_package(Protobuf REQUIRED)

# specify include directories and generate C++
include_directories(${PROTOBUF_INCLUDE_DIR})

# this is needed on FreeBSD for it to find the any.proto definition
set(PROTOBUF_IMPORT_DIRS "${PROTOBUF_INCLUDE_DIR};${PROTOBUF_IMPORT_DIRS}")

protobuf_generate_cpp(PROTO_SRC PROTO_HEADER Message.proto AuthToken.proto)

# specify it as a library
add_library(lichtensteinProtobufsShared OBJECT ${PROTO_HEADER} ${PROTO_SRC})