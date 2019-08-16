//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_TLSSERVER_H
#define LIBLICHTENSTEIN_TLSSERVER_H

#include <string>
#include <memory>
#include <vector>

#include <openssl/ssl.h>

namespace liblichtenstein {
  class TLSClient;

  /**
   * Provides a basic server that encrypts all communication with TLS.
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
  class TLSServer {
    public:
      explicit TLSServer(int fd);
      virtual ~TLSServer();

    public:
      void loadCert(std::string certPath, std::string keyPath);

      std::shared_ptr<TLSClient> run();

    private:
      void createContext();

    private:
      /// listening socket
      int listeningSocket = -1;

      /// SSL context
      SSL_CTX *ctx = nullptr;

      /// a list of all clients we've accepted.
      std::vector<std::shared_ptr<TLSClient>> clients;
  };
}


#endif //LIBLICHTENSTEIN_TLSSERVER_H
