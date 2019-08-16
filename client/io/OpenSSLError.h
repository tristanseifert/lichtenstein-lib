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
      OpenSSLError() : std::runtime_error("") {
        this->sslErrs = OpenSSLError::getSSLErrors();
      }

      explicit OpenSSLError(std::string desc) : description(desc), std::runtime_error("") {
        this->sslErrs = OpenSSLError::getSSLErrors();
      }

      virtual const char *what() const noexcept {
        std::string both = this->description + " (" + this->sslErrs + ")";
        return both.c_str();
      }

    private:
      // OpenSSL errors at time of instantiation
      std::string sslErrs;
      // optional user-provided description
      std::string description;

      static std::string getSSLErrors();
  };
}

#endif //LIBLICHTENSTEIN_OPENSSLERROR_H
