//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_TLSCLIENT_H
#define LIBLICHTENSTEIN_TLSCLIENT_H

#include <vector>
#include <cstddef>

#include <arpa/inet.h>

#include <openssl/ssl.h>

namespace liblichtenstein {
  class GenericTLSServer;

  /**
   * This object represents a client to a TLSServer. It roughly wraps a socket
   * and SSL context.
   *
   * You should never create an instance of this class directly. Rather, the
   * `TLSServer` class will create one with the appropriate fields filled in and
   * return it.
   */
  class TLSClient {
    friend class TLSServer;

    protected:
      TLSClient(GenericTLSServer *server, int fd, SSL *ctx,
                struct sockaddr_in addr);
    public:
      TLSClient() = delete;
      virtual ~TLSClient();

    public:
      [[nodiscard]]bool isSessionOpen() const {
        return this->isOpen;
      }
      void close();

      size_t write(const std::vector<std::byte> &data);

      size_t read(std::vector<std::byte> &data, size_t wanted);

      [[nodiscard]] size_t pending() const;

      [[nodiscard]] GenericTLSServer *getServer() const {
        return this->server;
      }

    private:
      /// server associated with this client
      GenericTLSServer *server = nullptr;

      /// file descriptor (socket) that this client is bound to
      int fd = -1;
      /// SSL context used to interact with the client
      SSL *ctx = nullptr;
      /// address from which the client connected
      struct sockaddr_in clientAddr;

      /// whether the client connection is open
      bool isOpen = true;
  };
}


#endif //LIBLICHTENSTEIN_TLSCLIENT_H
