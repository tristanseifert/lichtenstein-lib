# pull in protobuf lib
include(FindProtobuf)
find_package(Protobuf REQUIRED)

# specify include directories and generate C++
include_directories(${PROTOBUF_INCLUDE_DIR})

protobuf_generate_cpp(PROTO_SRC PROTO_HEADER ChannelDescriptor.proto JoinChannel.proto JoinChannelAck.proto ChannelData.proto LeaveChannel.proto LeaveChannelAck.proto MulticastOutputReq.proto ChannelDataAck.proto)

# specify it as a library
add_library(lichtensteinProtobufsRt OBJECT ${PROTO_HEADER} ${PROTO_SRC})