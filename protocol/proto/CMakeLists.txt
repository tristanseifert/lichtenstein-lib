# pull in protobuf lib
include(FindProtobuf)
find_package(Protobuf REQUIRED)

# specify include directories and generate C++
include_directories(${PROTOBUF_INCLUDE_DIR})

# files to add
protobuf_generate_cpp(PROTO_SRC1 PROTO_HEADER1 Message.proto)
protobuf_generate_cpp(PROTO_SRC2 PROTO_HEADER2 server/ReqPing.proto server/RespPong.proto)
protobuf_generate_cpp(PROTO_SRC3 PROTO_HEADER3 rt/ChannelDescriptor.proto rt/JoinChannel.proto rt/JoinChannelAck.proto rt/ChannelData.proto rt/LeaveChannel.proto rt/LeaveChannelAck.proto)

set(PROTO_SRC ${PROTO_SRC1} ${PROTO_SRC2} ${PROTO_SRC3})
set(PROTO_HEADER ${PROTO_HEADER1} ${PROTO_HEADER2} ${PROTO_HEADER3})

# specify it as a library
add_library(lichtensteinProtobufs STATIC ${PROTO_HEADER} ${PROTO_SRC})