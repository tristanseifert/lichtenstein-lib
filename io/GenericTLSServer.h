//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_GENERICTLSSERVER_H
#define LIBLICHTENSTEIN_GENERICTLSSERVER_H

#include <string>
#include <memory>
#include <vector>

#include <openssl/ssl.h>

namespace liblichtenstein {
  namespace io {
    class GenericServerClient;

    class GenericTLSServer {
      public:
        explicit GenericTLSServer(int fd) : listeningSocket(fd) {};

        virtual ~GenericTLSServer();

      public:
        virtual void
        loadCert(const std::string &certPath, const std::string &keyPath);

        virtual std::shared_ptr<GenericServerClient> run() = 0;

      protected:
        /// listening socket
        int listeningSocket = -1;

        /// SSL context
        SSL_CTX *ctx = nullptr;

        /// a list of all clients we've accepted.
        std::vector<std::shared_ptr<GenericServerClient>> clients;
    };
  }
}

#endif //LIBLICHTENSTEIN_GENERICTLSSERVER_H
