//
// Created by Tristan Seifert on 2019-08-15.
//

#include "TLSServer.h"
#include "TLSClient.h"
#include "OpenSSLError.h"

#include <glog/logging.h>

#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <system_error>
#include <memory>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>



namespace liblichtenstein {
  /**
   * Initializes the TLS server.
   *
   * @param fd Socket to listen on; this should already be configured for
   * listening purposes.
   */
  TLSServer::TLSServer(int fd) : GenericTLSServer(fd) {
    // set up OpenSSL context
    this->createContext();
  }

  /**
   * Tears down the TLS server. Any existing sessions are closed.
   */
  TLSServer::~TLSServer() {
  }



  /**
   * Creates the OpenSSL context for TLS; we create it with TLS 1.2.
   *
   * The context is configured to automatically select the highest strength
   * ECDH curve during key negotiation.
   *
   * @throws TLSServer::OpenSSLError
   */
  void TLSServer::createContext() {
    // try to create an SSL context
    const SSL_METHOD *method;
    method = TLSv1_2_server_method();

    this->ctx = SSL_CTX_new(method);
    if(this->ctx == nullptr) {
      throw OpenSSLError("SSL_CTX_new() failed");
    }

    // configure the context
    SSL_CTX_set_ecdh_auto(this->ctx, 1);
  }



  /**
   * Waits to accept a new connection on the listening socket.
   *
   * @return A reference to a the accepted client
   * @throws std::system_error, TLSServer::OpenSSLError
   */
  std::shared_ptr<TLSClient> TLSServer::run() {
    // store the address of the client and prepare an SSL context
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);

    memset(&addr, 0, addrLen);

    SSL *ssl;

    // wait for a client
    int clientFd = accept(this->listeningSocket, reinterpret_cast<struct sockaddr *>(&addr), &addrLen);

    if (clientFd < 0) {
      throw std::system_error(clientFd, std::system_category(), "accept() failed");
    }

    // we've got a client, try to create an SSL session
    VLOG(1) << "Got new client with FD " << clientFd;

    ssl = SSL_new(this->ctx);
    SSL_set_fd(ssl, clientFd);

    if(SSL_accept(ssl) <= 0) {
      throw OpenSSLError("SSL_accept() failed");
    }

    // the handshake was successful
    auto *client = new TLSClient(this, clientFd, ssl, addr);
    return this->clients.emplace_back(client);
  }
}