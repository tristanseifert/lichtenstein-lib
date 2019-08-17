# define the library
add_library(lichtensteinClient SHARED version.c version.h io/TLSServer.cpp io/TLSServer.h io/GenericServerClient.cpp io/GenericServerClient.h io/OpenSSLError.cpp io/OpenSSLError.h io/DTLSServer.cpp io/DTLSServer.h io/GenericTLSServer.h io/GenericTLSServer.cpp io/GenericTLSClient.cpp io/GenericTLSClient.h io/DTLSClient.cpp io/DTLSClient.h io/TLSClient.cpp io/TLSClient.h)

# link with the protobufs for the lichtenstein wire protocols
target_link_libraries(lichtensteinClient lichtensteinProto)

# also, link against OpenSSL and glog
find_package(OpenSSL REQUIRED)
target_link_libraries(lichtensteinClient OpenSSL::SSL OpenSSL::Crypto)

find_package(glog REQUIRED)
target_link_libraries(lichtensteinClient glog::glog)