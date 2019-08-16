//
// Created by Tristan Seifert on 2019-08-15.
//

#include "OpenSSLError.h"

#include <iostream>
#include <stdexcept>
#include <string>

#include <openssl/err.h>



namespace liblichtenstein {
  /**
   * Allocates an OpenSSL error without a description.
   */
  OpenSSLError::OpenSSLError() : std::runtime_error("") {
    OpenSSLError("General OpenSSL error");
  }

  /**
   * Allocates an OpenSSL error with a description.
   *
   * @param desc Description to store
   */
  OpenSSLError::OpenSSLError(std::string desc) : description(desc), std::runtime_error("") {
    this->sslErrs = OpenSSLError::getSSLErrors();
    this->whatStr = this->description + " (" + this->sslErrs + ")";
  }

  /**
   * Gets all pending OpenSSL errors into a string.
   *
   * @return All pending OpenSSL errors
   */
  std::string OpenSSLError::getSSLErrors() {
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
//    std::cerr << str << std::endl;
    return str;
  }
}