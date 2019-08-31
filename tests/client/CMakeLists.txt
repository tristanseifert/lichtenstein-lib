# create client executable
add_executable(client client.cpp BasicFileDataStore.cpp BasicFileDataStore.h)

# include stduuid library
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libs/stduuid/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../)

# link lichtenstein client lib
target_link_libraries(client lichtensteinClient)

# link with glog
find_package(glog REQUIRED)
target_link_libraries(client glog::glog)

# link with LibreSSL
find_package(LibreSSL REQUIRED)

if (APPLE)
    # a kind of nasty hack for macOS, otherwise it will link with system OpenSSL :(
    include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
    target_link_libraries(client /usr/local/opt/libressl/lib/libcrypto.dylib /usr/local/opt/libressl/lib/libssl.dylib /usr/local/opt/libressl/lib/libtls.dylib)
else ()
    target_link_libraries(client LibreSSL::TLS)
endif ()
