//
// Created by Tristan Seifert on 2019-08-16.
//

#include "TLSClient.h"
#include "OpenSSLError.h"

#include <glog/logging.h>

#include <iostream>
#include <cstddef>
#include <utility>
#include <vector>
#include <string>
#include <stdexcept>
#include <system_error>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <netdb.h>

namespace liblichtenstein {
  /**
   * Sets up the TLS client.
   *
   * @param host Hostname (such as 172.16.12.1) to connect to
   * @param port Port to connect to
   *
   * @throws OpenSSLError, std::system_error
   */
  TLSClient::TLSClient(std::string host, int port) : GenericTLSClient(
          std::move(host),
          port) {
    int err, errType;

    // clear some variables
    memset(&this->connectedAddr, 0, sizeof(this->connectedAddr));

    // create the context
    this->createContext();

    // try to connect
    err = SSL_connect(this->ssl);

    if (err <= 0) {
      // can we get specific info on the error?
      if (err < 0) {
        // figure out what went wrong
        errType = SSL_get_error(this->ssl, err);

        if (errType == SSL_ERROR_SYSCALL) {
          // a syscall failed, so forward that
          throw std::system_error(errno, std::system_category(),
                                  "SSL_connect() failed");
        } else if (errType == SSL_ERROR_ZERO_RETURN) {
          // the SSL session has been closed, so tear it down
          this->close();
        } else {
          // it was some other OpenSSL error
          throw OpenSSLError("SSL_connect() failed");
        }
      }
      // general OpenSSL error
      throw OpenSSLError("SSL_connect() failed: " + std::to_string(err));
    }

    VLOG(1) << "TLS handshake complete";
  }

  /**
   * Tears down the DTLS session.
   */
  TLSClient::~TLSClient() {
    // close socket if needed
    if (this->connectedSocket > 0) {
      ::close(this->connectedSocket);
      this->connectedSocket = -1;
    }
  }

  /**
   * Creates the TLS context.
   */
  void TLSClient::createContext() {
    // resolve the server and create a socket
    this->servinfo = TLSClient::resolveHost(this->serverHost, this->serverPort);
    this->createSocket();

    // create the basic context
    this->ctx = SSL_CTX_new(TLSv1_2_client_method());
    SSL_CTX_set_read_ahead(this->ctx, 1);

    // create SSL context
    this->ssl = SSL_new(this->ctx);

    if (this->ssl == nullptr) {
      throw OpenSSLError("SSL_new() failed");
    }

    // create a BIO for the socket, then attempt to connect it
    this->bio = BIO_new_socket(this->connectedSocket, BIO_CLOSE);

    this->connectSocket();

//    BIO_ctrl(this->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &this->connectedAddr);
    SSL_set_bio(this->ssl, this->bio, this->bio);

    // set connect mode and enable auto-retry
    SSL_set_mode(this->ssl, SSL_MODE_AUTO_RETRY);
  }

  /**
   * Creates the socket connected to the TLS server.
   */
  void TLSClient::createSocket() {
    // create the UDP socket (using IP address family of first result)
    this->connectedSocket = socket(this->servinfo->ai_family, SOCK_STREAM, 0);

    if (this->connectedSocket < 0) {
      throw std::system_error(errno, std::system_category(),
                              "could not create TCP socket");
    }
  }

  /**
   * Connects the socket to the first resolved address that works.
   */
  void TLSClient::connectSocket() {
    int err;

    struct addrinfo *p;

    // bind to the first one we can
    for (p = this->servinfo; p != nullptr; p = p->ai_next) {
      // perform connection
      err = connect(this->connectedSocket, p->ai_addr, p->ai_addrlen);

      this->connectedAddr = *p;

      if (err != 0) {
        throw std::system_error(errno, std::system_category(),
                                "could not connect TCP socket");
      }
    }

    // release addrinfo struct
    freeaddrinfo(this->servinfo);
    this->servinfo = nullptr;
  }
}