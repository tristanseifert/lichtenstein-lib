# define the library
add_library(lichtensteinClient SHARED version.c version.h io/TLSServer.cpp io/TLSServer.h io/TLSClient.cpp io/TLSClient.h io/OpenSSLError.cpp io/OpenSSLError.h)

# link with the protobufs for the lichtenstein wire protocols
target_link_libraries(lichtensteinClient lichtensteinProto)

# also, link against OpenSSL and glog
find_package(OpenSSL REQUIRED)
target_link_libraries(lichtensteinClient OpenSSL::SSL OpenSSL::Crypto)

find_package(glog 0.4.0 REQUIRED)
target_link_libraries(lichtensteinClient glog::glog)