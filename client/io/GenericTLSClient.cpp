//
// Created by Tristan Seifert on 2019-08-16.
//

#include "GenericTLSClient.h"

#include <glog/logging.h>

#include <openssl/ssl.h>

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
}