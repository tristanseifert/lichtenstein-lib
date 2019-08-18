//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_SSLSESSIONCLOSEDERROR_H
#define LIBLICHTENSTEIN_SSLSESSIONCLOSEDERROR_H

#include <stdexcept>
#include <string>

namespace liblichtenstein::io {
  /**
   * A basic error that indicates the the SSL session was closed for some
   * reason.
   */
  class SSLSessionClosedError : public std::runtime_error {
    public:
      explicit SSLSessionClosedError(const char *what) : std::runtime_error(
              what) {}
  };
}

#endif //LIBLICHTENSTEIN_SSLSESSIONCLOSEDERROR_H
