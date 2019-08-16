find_package(glog REQUIRED)

# define the library
add_executable(liblichtensteintests tests.cpp)

# link against the lichtenstein libs
target_link_libraries(liblichtensteintests lichtensteinClient)

# also, link in the testing library
find_package(Catch2 REQUIRED)
target_link_libraries(liblichtensteintests Catch2::Catch2)



###
# free standing TLS client
add_executable(dtlsclient dtls_client.cpp)
target_link_libraries(dtlsclient lichtensteinClient)
target_link_libraries(dtlsclient glog::glog)