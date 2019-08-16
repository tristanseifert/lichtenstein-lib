//
// Created by Tristan Seifert on 2019-08-15.
//

#include "TLSServer.h"

#include <glog/logging.h>

#include <string>
#include <stdexcept>
#include <system_error>

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
  TLSServer::TLSServer(int fd) : listeningSocket(fd) {
    // set up OpenSSL context
    this->createContext();
  }

  /**
   * Tears down the TLS server. Any existing sessions are closed.
   */
  TLSServer::~TLSServer() {
    // delete the context
    SSL_CTX_free(this->ctx);
    this->ctx = nullptr;
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
   * Loads a PEM-encoded certificate (and its corresponding private key) into
   * the OpenSSL context.
   *
   * @param certPath Path to PEM-encoded certificate
   * @param keyPath Path to PEM-encoded private key
   *
   * @throws TLSServer::OpenSSLError
   */
  void TLSServer::loadCert(std::string certPath, std::string keyPath) {
    // load certificate
    if(SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
      throw OpenSSLError("Could not load certificate");
    }

    // load private key
    if(SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
      throw OpenSSLError("Could not load private key");
    }
  }



  /**
   * Waits to accept a new connection on the listening socket.
   *
   * @throws std::system_error, TLSServer::OpenSSLError
   */
  void TLSServer::run() {
    // store the address of the client and prepare an SSL context
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);

    SSL *ssl;

    // wait for a client
    int client = accept(this->listeningSocket, reinterpret_cast<struct sockaddr *>(&addr), &addrLen);

    if (client < 0) {
      throw std::system_error(client, std::system_category(), "accept() failed");
    }

    // we've got a client, try to create an SSL session
    VLOG(1) << "Got new client with FD " << client;

    ssl = SSL_new(this->ctx);
    SSL_set_fd(ssl, client);

    if(SSL_accept(ssl) <= 0) {
      throw OpenSSLError("SSL_accept() failed");
    }

    // the handshake was successful
    // TODO: return client here
  }



  /**
   * Gets all pending OpenSSL errors into a string.
   *
   * @return All pending OpenSSL errors
   */
  std::string TLSServer::OpenSSLError::getSSLErrors() {
    // print the error string into a BIO
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);

    // get the contents of the BIO and create a string from it
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);

    std::string str(buf, len);

    // clean up BIO
    BIO_free(bio);

    // done, return our string
    return str;
  }
}