//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_TLSSERVER_H
#define LIBLICHTENSTEIN_TLSSERVER_H

#include <string>
#include <stdexcept>

#include <openssl/ssl.h>

namespace liblichtenstein {
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
      TLSServer(int fd);
      virtual ~TLSServer();

    public:
      void loadCert(std::string certPath, std::string keyPath);

      void run(void);

    private:
      void createContext(void);

    private:
      /// listening socket
      int listeningSocket = -1;

      /// SSL context
      SSL_CTX *ctx = nullptr;

    public:
      /**
       * Errors thrown by OpenSSL
       */
      class OpenSSLError : public std::runtime_error {
        public:
          OpenSSLError() : std::runtime_error("") {
            this->sslErrs = OpenSSLError::getSSLErrors();
          }

          OpenSSLError(std::string desc) : description(desc), std::runtime_error("") {
            this->sslErrs = OpenSSLError::getSSLErrors();
          }

          virtual const char *what() const noexcept {
            std::string both = this->description + " (" + this->sslErrs + ")";
            return both.c_str();
          }

        private:
          // OpenSSL errors at time of instantiation
          std::string sslErrs;
          // optional user-provided description
          std::string description;

          static std::string getSSLErrors(void);
      };
  };
}


#endif //LIBLICHTENSTEIN_TLSSERVER_H
