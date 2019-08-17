//
// Created by Tristan Seifert on 2019-08-16.
//

#ifndef LIBLICHTENSTEIN_GENERICTLSCLIENT_H
#define LIBLICHTENSTEIN_GENERICTLSCLIENT_H

#include <openssl/ssl.h>

#include <cstddef>
#include <vector>
#include <string>

#include <netdb.h>

namespace liblichtenstein {
  /**
   * This is an abstract class that implements the interface expected of a
   * TLS client. When creating the client, the IP (or hostname) plus a port
   * number is specified. OpenSSL will handle the underlying sockets.
   *
   * Various callbacks are available to control the certificate validation
   * and other parts of the session handshake.
   */
  class GenericTLSClient {
    public:
      explicit GenericTLSClient(std::string host, int port) : serverHost(
              std::move(host)), serverPort(port) {};

      virtual ~GenericTLSClient();

    public:
      [[nodiscard]] bool isSessionOpen() const {
        return this->isOpen;
      }
      void close();

      virtual size_t write(const std::vector<std::byte> &data);

      virtual size_t read(std::vector<std::byte> &data, size_t wanted);

      [[nodiscard]] virtual size_t pending() const;

    protected:
      static struct addrinfo *resolveHost(std::string &host, int port);

    protected:
      /// whether the connection is "open"
      bool isOpen = true;

      /// file descriptor that's connected to the server
      int connectedSocket = -1;

      /// hostname of the destination host
      std::string serverHost;
      /// port of the destination host
      int serverPort = -1;

      /// SSL context
      SSL_CTX *ctx = nullptr;

      /// SSL session
      SSL *ssl = nullptr;
      /// IO instance to communicate over this session
      BIO *bio = nullptr;
  };
}


#endif //LIBLICHTENSTEIN_GENERICTLSCLIENT_H
