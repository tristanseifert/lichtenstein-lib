//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_PROTOCOLERROR_H
#define LIBLICHTENSTEIN_PROTOCOLERROR_H

#include <stdexcept>

namespace liblichtenstein::api {
  /**
   * Represents an error that took place with the lichtenstein API protocol,
   * typically in deserializing a message or corrupted data.
   */
  class ProtocolError : public std::runtime_error {
    public:
      explicit ProtocolError(const char *what) : std::runtime_error(what) {}
  };
}

#endif //LIBLICHTENSTEIN_PROTOCOLERROR_H
