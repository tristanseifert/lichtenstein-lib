# define the library
add_library(lichtensteinClient SHARED version.c version.h Client.cpp Client.h api/API.cpp api/API.h api/ClientHandler.cpp api/ClientHandler.h api/IRequestHandler.h api/handlers/GetInfoReq.cpp api/handlers/GetInfoReq.h api/HandlerFactory.cpp api/HandlerFactory.h IClientDataStore.h helpers/HmacChallengeHandler.cpp helpers/HmacChallengeHandler.h RealtimeClient.cpp RealtimeClient.h api/handlers/AdoptRequest.cpp api/handlers/AdoptRequest.h)


# get Git info and compile it into the binary
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

target_sources(lichtensteinClient PRIVATE ${version_file})

# link with the protobufs and IO libs
target_link_libraries(lichtensteinClient lichtensteinProto lichtensteinIo)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/../protocol/proto)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

# include the stduuid library
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libs/stduuid/include)


# also, link against LibreSSL
find_package(LibreSSL REQUIRED)

if (APPLE)
    # a kind of nasty hack for macOS, otherwise it will link with system OpenSSL :(
    include_directories(BEFORE SYSTEM /usr/local/opt/libressl/include)
    target_link_libraries(lichtensteinClient /usr/local/opt/libressl/lib/libcrypto.dylib /usr/local/opt/libressl/lib/libssl.dylib /usr/local/opt/libressl/lib/libtls.dylib)
else ()
    target_link_libraries(lichtensteinClient LibreSSL::TLS)
endif ()

# other libraries (glog)
find_package(glog REQUIRED)
target_link_libraries(lichtensteinClient glog::glog)