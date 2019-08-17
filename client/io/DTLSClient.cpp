//
// Created by Tristan Seifert on 2019-08-16.
//
#include "DTLSClient.h"
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
   * Sets up the DTLS client.
   *
   * @param host Hostname (such as 172.16.12.1) to connect to
   * @param port Port to connect to
   *
   * @throws OpenSSLError, std::system_error
   */
  DTLSClient::DTLSClient(std::string host, int port) : GenericTLSClient(
          std::move(host), port) {
    int err, errType;

    // clear some variables
    memset(&this->connectedAddr, 0, sizeof(this->connectedAddr));

    // create the context
    this->createContext();

    // try to connect
    err = SSL_connect(this->ssl);

    if(err <= 0) {
      // can we get specific info on the error?
      if(err < 0) {
        // figure out what went wrong
        errType = SSL_get_error(this->ssl, err);

        if(errType == SSL_ERROR_SYSCALL) {
          // a syscall failed, so forward that
          throw std::system_error(errno, std::system_category(), "SSL_connect() failed");
        } else if(errType == SSL_ERROR_ZERO_RETURN) {
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

    // configure timeouts on the DTLS socket
    VLOG(1) << "DTLS handshake complete";

    struct timeval timeout{};
    memset(&timeout, 0, sizeof(timeout));

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    BIO_ctrl(this->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
  }

  /**
   * Tears down the DTLS session.
   */
  DTLSClient::~DTLSClient() {
    // close socket if needed
    if(this->connectedSocket > 0) {
      ::close(this->connectedSocket);
      this->connectedSocket = -1;
    }
  }



  /**
   * Sets up the DTLS client context.
   *
   * @throws OpenSSLError, std::system_error
   */
  void DTLSClient::createContext() {
    // resolve the server and create a socket
    this->servinfo = DTLSClient::resolveHost(this->serverHost,
                                             this->serverPort);
    this->createSocket();

    // create the basic context
    this->ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_read_ahead(this->ctx, 1);

    // create SSL context
    this->ssl = SSL_new(this->ctx);

    if(this->ssl == nullptr) {
      throw OpenSSLError("SSL_new() failed");
    }

    // create a BIO for the socket, then attempt to connect it
    this->bio = BIO_new_dgram(this->connectedSocket, BIO_CLOSE);

    this->connectSocket();

    BIO_ctrl(this->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &this->connectedAddr);
    SSL_set_bio(this->ssl, this->bio, this->bio);

    // set connect mode and enable auto-retry
//    SSL_set_mode(this->ssl, SSL_MODE_AUTO_RETRY);
  }

  /**
   * Creates the UDP socket to connect to the server.
   */
  void DTLSClient::createSocket() {
    // create the UDP socket (using IP address family of first result)
    this->connectedSocket = socket(this->servinfo->ai_family, SOCK_DGRAM, 0);

    if(this->connectedSocket < 0) {
      throw std::system_error(errno, std::system_category(), "could not create UDP socket");
    }
  }

  /**
   * Connects the UDP socket.
   */
  void DTLSClient::connectSocket() {
    int err;

    struct addrinfo *p;

    // bind to the first one we can
    for(p = this->servinfo; p != nullptr; p = p->ai_next) {
      // perform connection
      err = connect(this->connectedSocket, p->ai_addr, p->ai_addrlen);

      this->connectedAddr = *p;

      if(err != 0) {
        throw std::system_error(errno, std::system_category(), "could not connect UDP socket");
      }
    }

    // release addrinfo struct
    freeaddrinfo(this->servinfo);
    this->servinfo = nullptr;
  }
}