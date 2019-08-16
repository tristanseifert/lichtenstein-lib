//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_OPENSSLERROR_H
#define LIBLICHTENSTEIN_OPENSSLERROR_H

#include <stdexcept>
#include <string>

namespace liblichtenstein {
  /**
   * Errors thrown by OpenSSL
   */
  class OpenSSLError : public std::runtime_error {
    public:
      OpenSSLError();

      explicit OpenSSLError(std::string desc);

      virtual const char *what() const noexcept {
        return this->whatStr.c_str();
      }

    private:
      // OpenSSL errors at time of instantiation
      std::string sslErrs;
      // optional user-provided description
      std::string description;

      /// full "what()" string
      std::string whatStr;

      static std::string getSSLErrors();
  };
}

#endif //LIBLICHTENSTEIN_OPENSSLERROR_H
