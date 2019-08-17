//
// Created by Tristan Seifert on 2019-08-16.
//

#include "GenericTLSClient.h"
#include "OpenSSLError.h"

#include <glog/logging.h>

#include <openssl/ssl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>



namespace liblichtenstein {
  /**
   * Tears down the SSL context, then closes the socket.
   */
  GenericTLSClient::~GenericTLSClient() {
    // close and deallocate the session
    if(this->isOpen) {
      this->close();
    }

    if(this->ssl) {
      SSL_free(this->ssl);
      this->ssl = nullptr;
    }

    // clean up the SSL context too
    if(this->ctx) {
      SSL_CTX_free(this->ctx);
      this->ctx = nullptr;
    }
  }


  /**
   * Attempts to cleanly shut down the SSL session.
   */
  void GenericTLSClient::close() {
    int err, errType;

    // mark connection as closed
    this->isOpen = false;

    // abort if we have no SSL context
    if(this->ssl == nullptr) return;

    // try sending the shutdown notification
    err = SSL_shutdown(this->ssl);

    // shutdown not yet complete; call it again
    if(err == 0) {
      return this->close();
    }
    // shutdown completed
    else if(err == 1) {
      // close socket (fall through)
    }
    // another type of error :(
    else if(err < 0) {
      errType = SSL_get_error(this->ssl, err);

      // XXX: should this error be ignored?
    }

    // go ahead and close the socket (TODO: should we check errors?)
    ::close(this->connectedSocket);
    this->connectedSocket = -1;
  }


  /**
   * Writes data to the SSL session.
   *
   * @param data Vector of data to write
   * @return Actual number of bytes written
   */
  size_t GenericTLSClient::write(const std::vector<std::byte> &data) {
    int err, errType;

    // pull out pointers to data
    const std::byte *buf = data.data();
    const size_t bufSz = data.size();


    // perform write
    err = SSL_write(this->ssl, buf, bufSz);

    if (err <= 0) {
      // figure out what went wrong
      errType = SSL_get_error(this->ssl, err);

      if (errType == SSL_ERROR_SYSCALL) {
        // a syscall failed, so forward that
        throw std::system_error(errno, std::system_category(),
                                "SSL_write() failed");
      } else if (errType == SSL_ERROR_ZERO_RETURN) {
        // the SSL session has been closed, so tear it down
        this->close();
      } else {
        // it was some other OpenSSL error
        throw OpenSSLError("SSL_write() failed");
      }
    }

    // write was successful. return number of bytes written
    return err;
  }

  /**
   * Attempts to read from the SSL session. Data is appended to the specified
   * vector, up to `wanted` bytes.
   *
   * @param data Vector into which data is appended
   * @param wanted Maximum number of bytes to read
   * @return Actual number of bytes read
   */
  size_t GenericTLSClient::read(std::vector<std::byte> &data, size_t wanted) {
    int err, errType;

    // create a temporary buffer
    std::vector<std::byte> buffer;
    buffer.reserve(wanted);

    std::byte *buf = buffer.data();

    // try to read
    err = SSL_read(this->ssl, buf, wanted);

    if (err <= 0) {
      // figure out what went wrong
      errType = SSL_get_error(this->ssl, err);

      if (errType == SSL_ERROR_SYSCALL) {
        // a syscall failed, so forward that
        throw std::system_error(errno, std::system_category(),
                                "SSL_read() failed");
      } else if (errType == SSL_ERROR_ZERO_RETURN) {
        // the SSL session has been closed, so tear it down
        this->close();
      } else if (errType == SSL_ERROR_WANT_READ) {
        // no data is available on the socket for us to consume
        return 0;
      } else {
        // it was some other OpenSSL error
        throw OpenSSLError(
                "SSL_read() failed (err = " + std::to_string(errType) + ")");
      }
    }

    // read was successful, copy the bytes and return
    data.insert(data.end(), buffer.begin(), (buffer.begin() + err));

    return err;
  }
  /**
   * Gets the number of bytes pending to be read from the session.
   *
   * @return Bytes of data pending in session buffer
   */
  size_t GenericTLSClient::pending() const {
    int err;

    // get pending count
    err = SSL_pending(this->ssl);

    return err;
  }


  /**
   * Resolves the given hostname and port
   */
  struct addrinfo *GenericTLSClient::resolveHost(std::string &host, int port) {
    int err;

    struct addrinfo hints{}, *out;
    memset(&hints, 0, sizeof(hints));

    // configure hints when resolving
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    // try to resolve hostname
    const char *hostname = host.c_str();
    const char *portStr = (std::to_string(port)).c_str();

    err = getaddrinfo(hostname, portStr, &hints, &out);

    if (err != 0) {
      throw std::system_error(errno, std::system_category(),
                              "error resolving hostname");
    }

    return out;
  }
}