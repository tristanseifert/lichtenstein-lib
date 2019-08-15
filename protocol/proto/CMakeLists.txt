# create the protobufs lib as an interface
#add_library(lichtensteinProtobufs)

# pull in the static protobuf libraries
add_subdirectory(rt)
#target_link_libraries(lichtensteinProtobufs INTERFACE lichtensteinProtobufsRt)

add_subdirectory(server)
#target_link_libraries(lichtensteinProtobufs INTERFACE lichtensteinProtobufsServer)

add_subdirectory(client)
#target_link_libraries(lichtensteinProtobufs INTERFACE lichtensteinProtobufsClient)

add_subdirectory(shared)
#target_link_libraries(lichtensteinProtobufs INTERFACE lichtensteinProtobufsShared)

# combine all four built libraries
#add_custom_command(
#    OUTPUT liblichtensteinProtobufsCombined.a
#    COMMAND ${CMAKE_CXX_ARCHIVE_CREATE} liblichtensteinProtobufsCombined.a $<TARGET_FILE:lichtensteinProtobufsRt> $<TARGET_FILE:lichtensteinProtobufsServer> $<TARGET_FILE:lichtensteinProtobufsClient> $<TARGET_FILE:lichtensteinProtobufsShared>
#    DEPENDS lichtensteinProtobufsRt lichtensteinProtobufsServer lichtensteinProtobufsClient lichtensteinProtobufsShared
#)
#add_custom_target(lichtensteinProtobufs
#    DEPENDS libLichtensteinProtobufsCombined.a
#)