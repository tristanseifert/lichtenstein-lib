//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_DTLSSERVER_H
#define LIBLICHTENSTEIN_DTLSSERVER_H

#include "GenericTLSServer.h"

namespace liblichtenstein {
  namespace io {
    /**
     * Provides a basic server that encrypts all communication with DTLS, which
     * typically runs on an UDP socket, but DTLS works with all datagram-style
     * network protocols.
     *
     * To use, create a server instance with a file descriptor (e.g. a socket)
     * and configure a certificate and corresponding private key.
     *
     * Once configured, enter the server's main loop `run()` which will wait for
     * new connections on the socket, and try to establish a TLS session with
     * them. When a session is established (or an error occurs) this function
     * will return.
     *
     * @note OpenSSL _must_ be initialized before trying to construct this class.
     */
    class DTLSServer : public GenericTLSServer {
      public:
        explicit DTLSServer(int fd);

        virtual ~DTLSServer();

      public:
        virtual std::shared_ptr<GenericServerClient> run();

      private:
        void createContext();
    };
  }
}


#endif //LIBLICHTENSTEIN_DTLSSERVER_H
