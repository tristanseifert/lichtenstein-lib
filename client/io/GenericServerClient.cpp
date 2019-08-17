//
// Created by Tristan Seifert on 2019-08-15.
//

#include "GenericServerClient.h"
#include "TLSServer.h"
#include "OpenSSLError.h"

#include <glog/logging.h>

#include <vector>
#include <stdexcept>
#include <system_error>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>



namespace liblichtenstein {
  /**
   * Creates a new TLS client.
   *
   * @note This client instance assumes ownership of the socket and SSL context,
   * and will deallocate both when deleted.
   *
   * @param _server Server to which this client connected
   * @param _fd Socket that the client is bound to
   * @param _ctx SSL context associated with this socket
   * @param _addr Address from which the client connected
   */
  GenericServerClient::GenericServerClient(GenericTLSServer *_server, int _fd, SSL *_ctx,
                                           struct sockaddr_in _addr) : server(_server), fd(_fd),
                                                   ctx(_ctx),
                                                   clientAddr(_addr) {
    CHECK_NOTNULL(_server);
    CHECK_NOTNULL(_ctx);
  }

  /**
   * Destroys a TLS client instance.
   *
   * This deallocates the SSL context, then closes the socket.
   */
  GenericServerClient::~GenericServerClient() {
    // close and deallocate the session
    if(this->isOpen) {
      this->close();
    }

    if(this->ctx) {
      SSL_free(this->ctx);
      this->ctx = nullptr;
    }

    // just set the server ptr to null
    this->server = nullptr;
  }


  /**
   * Closes the connection; this performs a clean shutdown of the SSL session,
   * then actually closes the socket.
   *
   * @note This does not actually deallocate the underlying SSL context.
   */
  void GenericServerClient::close() {
    int err, errType;

    // mark connection as closed
    this->isOpen = false;

    // try sending the shutdown notification
    err = SSL_shutdown(this->ctx);

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
      errType = SSL_get_error(this->ctx, err);

      // XXX: should this error be ignored?
    }

    // go ahead and close the socket (TODO: should we check errors?)
    ::close(this->fd);
  }

  /**
   * Writes data to the client through the SSL session. This invokes OpenSSL to
   * properly encrypt the data.
   *
   * @param data Bytes to write to the connection
   * @return Number of bytes written
   * @throws std::system_error, TLSServer::OpenSSLError
   */
  size_t GenericServerClient::write(const std::vector<std::byte> &data) {
    int err, errType;

    // pull out pointers to data
    const std::byte *buf = data.data();
    const size_t bufSz = data.size();


    // perform write
    err = SSL_write(this->ctx, buf, bufSz);

    if(err <= 0) {
      // figure out what went wrong
      errType = SSL_get_error(this->ctx, err);

      if(errType == SSL_ERROR_SYSCALL) {
        // a syscall failed, so forward that
        throw std::system_error(errno, std::system_category(), "SSL_write() failed");
      } else if(errType == SSL_ERROR_ZERO_RETURN) {
        // the SSL session has been closed, so tear it down
        this->close();
      } else {
        // it was some other OpenSSL error
        throw OpenSSLError(
                "SSL_write() failed (type " + std::to_string(errType) +
                ", err " + std::to_string(err) + ")");
      }
    }

    // write was successful. return number of bytes written
    return err;
  }

  /**
   * Reads data from the connection through the SSL connection. Since data in
   * TLS is based on records, we can only process entire records at a time, so
   * extra data may be available.
   *
   * @param data Vector into which data should be read
   * @param wanted How many bytes are desired to read
   * @return How many bytes were actually read
   * @throws std::system_error, TLSServer::OpenSSLError
   */
  size_t GenericServerClient::read(std::vector<std::byte> &data, size_t wanted) {
    int err, errType;

    // create a temporary buffer
    std::vector<std::byte> buffer;
    buffer.reserve(wanted);

    std::byte *buf = buffer.data();

    // try to read
    err = SSL_read(this->ctx, buf, wanted);

    if(err <= 0) {
      // figure out what went wrong
      errType = SSL_get_error(this->ctx, err);

      if(errType == SSL_ERROR_SYSCALL) {
        // a syscall failed, so forward that
        throw std::system_error(errno, std::system_category(), "SSL_read() failed");
      } else if (errType == SSL_ERROR_WANT_READ) {
        // no data is available on the socket for us to consume
        return 0;
      } else if (errType == SSL_ERROR_ZERO_RETURN) {
        // the SSL session has been closed, so tear it down
        this->close();
      } else {
        // it was some other OpenSSL error
        throw OpenSSLError(
                "SSL_write() failed (type " + std::to_string(errType) +
                ", err " + std::to_string(err) + ")");
      }
    }

    // read was successful, copy the bytes and return
    data.insert(data.end(), buffer.begin(), (buffer.begin() + err));

    return err;
  }

  /**
   * Gets the number of bytes pending to be read from the client.
   *
   * @return Number of bytes pending
   */
  size_t GenericServerClient::pending() const {
    int err;

    // get pending count
    err = SSL_pending(this->ctx);

    return err;
  }
}