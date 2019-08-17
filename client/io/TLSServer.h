//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_TLSSERVER_H
#define LIBLICHTENSTEIN_TLSSERVER_H

#include "GenericTLSServer.h"

namespace liblichtenstein {
  namespace io {
    class GenericServerClient;

    /**
     * Provides a basic server that encrypts all communication with TLS,
     * typically on a TCP socket.
     *
     * To use, create a server instance with a file descriptor (e.g. a socket)
     * and configure a certificate and corresponding private key.
     *
     * Once configured, enter the server's main loop `run()` which will wait for
     * new connections on the socket, and try to establish a TLS session with
     * them. When a session is established (or an error occurs) this function
     * will return.
     *
     * @note OpenSSL _must_ be initialized before trying to construct this class
     */
    class TLSServer : public GenericTLSServer {
      public:
        explicit TLSServer(int fd);

        virtual ~TLSServer();

      public:
        virtual std::shared_ptr<GenericServerClient> run();

      private:
        void createContext();
    };
  }
}


#endif //LIBLICHTENSTEIN_TLSSERVER_H
