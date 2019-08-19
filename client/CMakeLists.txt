find_package(LibreSSL REQUIRED)
find_package(glog REQUIRED)


# compile in the git version file
include(GetGitRevisionDescription)
git_describe(VERSION --tags --dirty=-d)

get_git_head_revision(GIT_REFSPEC GIT_HASH)

string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" VERSION_MAJOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" VERSION_MINOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" VERSION_PATCH "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.[0-9]+(.*)" "\\1" VERSION_SHA1 "${VERSION}")
set(VERSION_SHORT "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in
        ${CMAKE_CURRENT_BINARY_DIR}/version.cpp)
set(version_file "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")

# define the library
add_library(lichtensteinClient SHARED ${version_file} version.c version.h io/TLSServer.cpp io/TLSServer.h io/GenericServerClient.cpp io/GenericServerClient.h io/OpenSSLError.cpp io/OpenSSLError.h io/DTLSServer.cpp io/DTLSServer.h io/GenericTLSServer.h io/GenericTLSServer.cpp io/GenericTLSClient.cpp io/GenericTLSClient.h io/DTLSClient.cpp io/DTLSClient.h io/TLSClient.cpp io/TLSClient.h Client.cpp Client.h mdns/Service.h api/API.cpp api/API.h io/SSLSessionClosedError.h api/ClientHandler.cpp api/ClientHandler.h api/ProtocolError.h api/MessageSerializer.cpp api/MessageSerializer.h api/SerializationError.h)


# compile platform specific stuff into small shared libraries
if (APPLE)
    add_library(lichtensteinClientApple OBJECT mdns/AppleService.cpp mdns/AppleService.h)
    target_link_libraries(lichtensteinClientApple glog::glog)

    target_link_libraries(lichtensteinClient lichtensteinClientApple)
endif ()

# link with the protobufs for the lichtenstein wire protocols
target_link_libraries(lichtensteinClient lichtensteinProto)

include_directories(${CMAKE_BINARY_DIR}/protocol/proto)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)


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