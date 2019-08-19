//
// Created by Tristan Seifert on 2019-08-15.
//

#include "DTLSServer.h"
#include "OpenSSLError.h"
#include "GenericServerClient.h"

#include <glog/logging.h>

#include <string>
#include <vector>
#include <stdexcept>
#include <system_error>
#include <memory>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>



namespace liblichtenstein {
  namespace io {
    /**
     * Secret used to generate DTLS cookies: the first invocation of the DTLS
     * cookie generator will generate a random secret.
     */
    static bool cookieSecretValid = false;
    static const size_t cookieSecretLength = 16;
    static unsigned char cookieSecret[cookieSecretLength];

    int DTLSGenerateCookieCb(SSL *ssl, unsigned char *cookie,
                             unsigned int *cookieLen);

    int DTLSVerifyCookieCb(SSL *ssl, const unsigned char *cookie,
                           unsigned int cookieLen);

    int DTLSCalculateCookie(SSL *ssl, unsigned char *result,
                            unsigned int *resultLength);

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
      method = DTLS_server_method();

      this->ctx = SSL_CTX_new(method);
      if (this->ctx == nullptr) {
        throw OpenSSLError("SSL_CTX_new() failed");
      }

      // require client to present a cert
      //    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

      // set read-ahead and cookie verification callbacks
      SSL_CTX_set_read_ahead(this->ctx, 1);

      SSL_CTX_set_cookie_generate_cb(this->ctx, DTLSGenerateCookieCb);
      SSL_CTX_set_cookie_verify_cb(this->ctx, DTLSVerifyCookieCb);
    }


    /**
     * Waits to accept a new connection on the listening socket.
     *
     * @return A reference to a the accepted client
     * @throws std::system_error, TLSServer::OpenSSLError
     */
    std::shared_ptr<GenericServerClient> DTLSServer::run() {
      int err, errType, clientFd;

      // socket flags
      int on = 1, off = 0;

      // we receive the client address here
      union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
      } clientAddr, serverAddr;

      memset(&clientAddr, 0, sizeof(clientAddr));
      memset(&serverAddr, 0, sizeof(serverAddr));

      // temporary BIO for the socket
      BIO *bio = BIO_new_dgram(this->listeningSocket, BIO_NOCLOSE);

      // configure a timeout on the receiving socket
      struct timeval timeout;
      memset(&timeout, 0, sizeof(timeout));

      timeout.tv_sec = 2;
      BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

      // create a new SSL context for the new client
      SSL *ssl = SSL_new(this->ctx);

      // associate it with the BIO and enable DTLS cookie exchange
      SSL_set_bio(ssl, bio, bio);
      SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

      // listen for incoming requests
      while (DTLSv1_listen(ssl, &clientAddr) <= 0);


      // create a socket connected to this client
      clientFd = socket(clientAddr.ss.ss_family, SOCK_DGRAM, 0);

      if (clientFd < 0) {
        throw std::system_error(errno, std::system_category(),
                                "Could not open socket for client");
      }

      // allow addresses to be reused
      setsockopt(clientFd, SOL_SOCKET, SO_REUSEADDR, (const void *) &on,
                 (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
      setsockopt(clientFd, SOL_SOCKET, SO_REUSEPORT, (const void *) &on,
                 (socklen_t) sizeof(on));
#endif

      // read the server socket's address
      socklen_t serverAddrLen = sizeof(serverAddr);

      if (getsockname(this->listeningSocket, (struct sockaddr *) &serverAddr,
                      &serverAddrLen) == -1) {
        throw std::system_error(errno, std::system_category(),
                                "getsockname() failed");
      }


      // then, set up the local/remote addresses
      switch (clientAddr.ss.ss_family) {
        case AF_INET:
          // bind to local address and set the remote host's address
          if (bind(clientFd, (const struct sockaddr *) &serverAddr,
                   sizeof(struct sockaddr_in))) {
            throw std::system_error(errno, std::system_category(),
                                    "bind() on client socket");
          }
          if (connect(clientFd, (struct sockaddr *) &clientAddr,
                      sizeof(struct sockaddr_in))) {
            throw std::system_error(errno, std::system_category(),
                                    "connect() on client socket");
          }

          break;

        case AF_INET6:
          // disable IPv6 only option
          setsockopt(clientFd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &off,
                     sizeof(off));

          // then bind to local address, and set the remote host's address
          if (bind(clientFd, (const struct sockaddr *) &serverAddr,
                   sizeof(struct sockaddr_in6))) {
            throw std::system_error(errno, std::system_category(),
                                    "bind() on client socket");
          }
          if (connect(clientFd, (struct sockaddr *) &clientAddr,
                      sizeof(struct sockaddr_in6))) {
            throw std::system_error(errno, std::system_category(),
                                    "connect() on client socket");
          }
          break;

        default:
          throw std::runtime_error("Invalid address family " +
                                   std::to_string(clientAddr.ss.ss_family));
      }

      // lastly, associate it with the BIO
      BIO_set_fd(bio, clientFd, BIO_NOCLOSE);
      BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &clientAddr.ss);


      // complete the SSL handshake
      do {
        err = SSL_accept(ssl);

#ifdef IF_DEBUG_MODE
        // was there an error?
        if (err != 1) {
          // get error type
          errType = SSL_get_error(ssl, err);

          if (errType == SSL_ERROR_SYSCALL) {
            PLOG(ERROR) << "failed handshake";
          } else {
            LOG(INFO) << "error: " << err << ", error type: " << errType;
          }
        }
#endif
      } while (err == 0);

      // configure timeout on this client connection
      memset(&timeout, 0, sizeof(timeout));

      timeout.tv_sec = 2;
      BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

      // create client instance
      auto *client = new GenericServerClient(this, clientFd, ssl,
                                             clientAddr.s4);
      return this->clients.emplace_back(client);
    }


    /**
     * Generates a DTLS session cookie. This contains some random bytes, plus
     * the address/port of the connecting client.
     *
     * @param ssl SSL context for which to generate the cookie for
     * @param cookie Buffer into which we write the cookie
     * @param cookieLen Length of cookie, in bytes
     * @return 1 if successful, 0 otherwise.
     */
    int DTLSGenerateCookieCb(SSL *ssl, unsigned char *cookie,
                             unsigned int *cookieLen) {
      unsigned char result[EVP_MAX_MD_SIZE];
      unsigned int resultLength;

      // generate a random secret to use for cookies
      if (!cookieSecretValid) {
        if (!RAND_bytes(cookieSecret, cookieSecretLength)) {
          LOG(ERROR) << "Could not generate DTLS cookie secret!";
          return 0;
        }

        cookieSecretValid = true;
      }

      // calculate the cookie
      DTLSCalculateCookie(ssl, result, &resultLength);

      // copy cookie into result buffer
      memcpy(cookie, result, resultLength);
      *cookieLen = resultLength;

      return 1;
    }

    /**
     * Verifies a DTLS cookie.
     *
     * @param ssl SSL context on which we received the cookie
     * @param cookie Buffer containing the cookie
     * @param cookieLen Length of cookie, in bytes
     * @return 1 if the cookie was validated successfully, 0 otherwise.
     */
    int DTLSVerifyCookieCb(SSL *ssl, const unsigned char *cookie,
                           unsigned int cookieLen) {
      unsigned char result[EVP_MAX_MD_SIZE];
      unsigned int resultLength;

      // abort if cookie secret is not set
      if (!cookieSecretValid) {
        LOG(ERROR) << "Attempt to validate DTLS cookie (len = " << cookieLen
                   << ") but cookie secret has not been initialized";
        return 0;
      }
      // calculate the cookie
      DTLSCalculateCookie(ssl, result, &resultLength);

      // make sure it's valid (TODO: timing independent compare?)
      if (cookieLen == resultLength &&
          memcmp(result, cookie, resultLength) == 0) {
        // cookie was valid
        return 1;
      }

      // invalid cookie
      LOG(WARNING) << "DTLS cookie failed HMAC (len = " << cookieLen << ")";
      return 0;
    }

    /**
     * Given a client connected SSL context, generates the correct cookie value.
     *
     * @param ssl An SSL context
     * @param result Buffer into which cookie is written
     * @param resultLength Number of bytes of cookie generated
     * @return 0 if successful, an error code otherwise.
     */
    int DTLSCalculateCookie(SSL *ssl, unsigned char *result,
                            unsigned int *resultLength) {
      // size of the buffer to allocate
      unsigned int length = 0;
      // temporary buffer to write client address into
      unsigned char *buffer = nullptr;

      // this is where the client address will be read to
      union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
      } peer;
      memset(&peer, 0, sizeof(peer));


      // get peer information from BIO
      BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

      // get the number of bytes we need in our buffer
      length = 0;
      switch (peer.ss.ss_family) {
        case AF_INET:
          length += sizeof(struct in_addr);
          break;
        case AF_INET6:
          length += sizeof(struct in6_addr);
          break;
        default:
          LOG(ERROR) << "Invalid family: " << peer.ss.ss_family;
          return 0;
      }

      length += sizeof(in_port_t);

      // allocate cookie buffer
      buffer = (unsigned char *) OPENSSL_malloc(length);
      CHECK_NOTNULL(buffer);

      // copy the address and port into the buffer
      switch (peer.ss.ss_family) {
        case AF_INET:
          memcpy(buffer,
                 &peer.s4.sin_port,
                 sizeof(in_port_t));
          memcpy(buffer + sizeof(peer.s4.sin_port),
                 &peer.s4.sin_addr,
                 sizeof(struct in_addr));
          break;
        case AF_INET6:
          memcpy(buffer,
                 &peer.s6.sin6_port,
                 sizeof(in_port_t));
          memcpy(buffer + sizeof(in_port_t),
                 &peer.s6.sin6_addr,
                 sizeof(struct in6_addr));
          break;

        default:
          LOG(ERROR) << "Invalid family: " << peer.ss.ss_family;
          return 0;
      }

      // calculate a HMAC over the buffer using our secret
      HMAC(EVP_sha1(), (const void *) cookieSecret, cookieSecretLength,
           (const unsigned char *) buffer, length, result, resultLength);
      OPENSSL_free(buffer);

      // always success
      return 0;
    }
  }
}