find_package(glog REQUIRED)

# define the library
add_executable(liblichtensteintests tests.cpp)

# link against the lichtenstein libs
target_link_libraries(liblichtensteintests lichtensteinClient)

# also, link in the testing library
find_package(Catch2 REQUIRED)
target_link_libraries(liblichtensteintests Catch2::Catch2)


###
# client implementation test
add_subdirectory(client)

###
# free standing DTLS client
add_executable(dtlsclient dtls_client.cpp)
include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
target_link_libraries(dtlsclient lichtensteinClient)
target_link_libraries(dtlsclient glog::glog)

###
# free standing TLS client
add_executable(tlsclient tls_client.cpp)
include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
include_directories(${CMAKE_BINARY_DIR}/protocol/proto)
target_link_libraries(tlsclient lichtensteinClient)
target_link_libraries(tlsclient glog::glog)

###
# free standing DTLS server
add_executable(dtlsserver dtls_server.cpp)
include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
target_link_libraries(dtlsserver lichtensteinClient)
target_link_libraries(dtlsserver glog::glog)

###
# free standing TLS server
add_executable(tlsserver tls_server.cpp)
include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
target_link_libraries(tlsserver lichtensteinClient)
target_link_libraries(tlsserver glog::glog)