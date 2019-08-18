find_package(LibreSSL REQUIRED)
find_package(glog REQUIRED)

# define the library
add_library(lichtensteinClient SHARED version.c version.h io/TLSServer.cpp io/TLSServer.h io/GenericServerClient.cpp io/GenericServerClient.h io/OpenSSLError.cpp io/OpenSSLError.h io/DTLSServer.cpp io/DTLSServer.h io/GenericTLSServer.h io/GenericTLSServer.cpp io/GenericTLSClient.cpp io/GenericTLSClient.h io/DTLSClient.cpp io/DTLSClient.h io/TLSClient.cpp io/TLSClient.h Client.cpp Client.h mdns/Service.h)

# compile platform specific stuff into small shared libraries
if (APPLE)
    add_library(lichtensteinClientApple OBJECT mdns/AppleService.cpp mdns/AppleService.h)
    target_link_libraries(lichtensteinClientApple glog::glog)

    target_link_libraries(lichtensteinClient lichtensteinClientApple)
endif ()

# link with the protobufs for the lichtenstein wire protocols
target_link_libraries(lichtensteinClient lichtensteinProto)

# also, link against LibreSSL
if (APPLE)
    # a kind of nasty hack for macOS, otherwise it will link with system OpenSSL :(
    include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
    target_link_libraries(lichtensteinClient /usr/local/opt/libressl/lib/libcrypto.dylib /usr/local/opt/libressl/lib/libssl.dylib /usr/local/opt/libressl/lib/libtls.dylib)
else ()
    target_link_libraries(lichtensteinClient LibreSSL::TLS)
endif ()

# other libraries (glog)
target_link_libraries(lichtensteinClient glog::glog)