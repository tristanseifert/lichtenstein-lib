//
// Created by Tristan Seifert on 2019-08-15.
//

#include "DTLSServer.h"
#include "OpenSSLError.h"
#include "TLSClient.h"

#include <glog/logging.h>

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
   * Initializes the DTLS server.
   *
   * @param fd Socket to listen on; this should already be configured for
   * listening purposes.
   */
  DTLSServer::DTLSServer(int fd) : GenericTLSServer(fd) {
    // set up OpenSSL context
    this->createContext();
  }

  /**
   * Tears down the DTLS server. Any existing sessions are closed.
   */
  DTLSServer::~DTLSServer() {
  }


  /**
   * Creates the OpenSSL context for TLS; we create it with TLS 1.2.
   *
   * The context is configured to automatically select the highest strength
   * ECDH curve during key negotiation.
   *
   * @throws TLSServer::OpenSSLError
   */
  void DTLSServer::createContext() {
    // try to create an SSL context
    const SSL_METHOD *method;
    method = DTLSv1_server_method();

    this->ctx = SSL_CTX_new(method);
    if (this->ctx == nullptr) {
      throw OpenSSLError("SSL_CTX_new() failed");
    }
  }


  /**
   * Waits to accept a new connection on the listening socket.
   *
   * @return A reference to a the accepted client
   * @throws std::system_error, TLSServer::OpenSSLError
   */
  std::shared_ptr<TLSClient> DTLSServer::run() {
    // TODO: implement
  }
}