//
// Created by Tristan Seifert on 2019-08-15.
//

#include "OpenSSLError.h"

#include <stdexcept>
#include <string>

#include <openssl/err.h>



namespace liblichtenstein {
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
    return str;
  }
}