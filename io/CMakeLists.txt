find_package(LibreSSL REQUIRED)

# define static library
add_library(lichtensteinIo STATIC TLSServer.cpp TLSServer.h GenericServerClient.cpp GenericServerClient.h OpenSSLError.cpp OpenSSLError.h DTLSServer.cpp DTLSServer.h GenericTLSServer.h GenericTLSServer.cpp GenericTLSClient.cpp GenericTLSClient.h DTLSClient.cpp DTLSClient.h TLSClient.cpp TLSClient.h SSLSessionClosedError.h mdns/Service.h mdns/Service.cpp mdns/Browser.cpp mdns/Browser.h mdns/IBrowserService.h)


# compile mDNS stuff for various platforms
if (APPLE)
    add_library(lichtensteinIoApple OBJECT mdns/AppleService.cpp mdns/AppleService.h mdns/AppleBrowser.cpp mdns/AppleBrowser.h mdns/AppleBrowserService.cpp mdns/AppleBrowserService.h)
    target_link_libraries(lichtensteinIoApple glog::glog)

    target_link_libraries(lichtensteinIo lichtensteinIoApple)
endif ()


# link with LibreSSL
if (APPLE)
    # a kind of nasty hack for macOS, otherwise it will link with system OpenSSL :(
    include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
    target_link_libraries(lichtensteinIo /usr/local/opt/libressl/lib/libcrypto.dylib /usr/local/opt/libressl/lib/libssl.dylib /usr/local/opt/libressl/lib/libtls.dylib)
else ()
    target_link_libraries(lichtensteinIo LibreSSL::TLS)
endif ()

# link with glog
find_package(glog REQUIRED)
target_link_libraries(lichtensteinIo glog::glog)