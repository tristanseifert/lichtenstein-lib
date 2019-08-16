//
// Created by Tristan Seifert on 2019-08-15.
//
#include "GenericTLSServer.h"
#include "OpenSSLError.h"
#include "GenericServerClient.h"

#include <exception>

#include <glog/logging.h>

namespace liblichtenstein {
  /**
   * Tears down the TLS server. Any existing sessions are closed.
   */
  GenericTLSServer::~GenericTLSServer() {
    // close all connections
    for (auto client : this->clients) {
      if (client->isSessionOpen()) {
        // swallow any errors
        try {
          client->close();
        } catch (std::exception &e) {
          LOG(ERROR) << "Error closing client " << client << ": " << e.what();
        }
      }
    }

    // delete the context
    SSL_CTX_free(this->ctx);
    this->ctx = nullptr;
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
  void GenericTLSServer::loadCert(const std::string &certPath,
                                  const std::string &keyPath) {
    int err;

    // load certificate
    if (SSL_CTX_use_certificate_file(this->ctx, certPath.c_str(),
                                     SSL_FILETYPE_PEM) <= 0) {
      throw OpenSSLError("Could not load certificate");
    }

    // load private key
    if (SSL_CTX_use_PrivateKey_file(this->ctx, keyPath.c_str(),
                                    SSL_FILETYPE_PEM) <= 0) {
      throw OpenSSLError("Could not load private key");
    }

    // validate the private key
    err = SSL_CTX_check_private_key(this->ctx);

    if (err != 1) {
      throw OpenSSLError("Private key failed verification");
    }
  }
}