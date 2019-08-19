//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_SERIALIZATIONERROR_H
#define LIBLICHTENSTEIN_SERIALIZATIONERROR_H

#include <stdexcept>

namespace liblichtenstein::api {
  /**
   * Represents an error that took place while serializing a message; usually
   * this indicates that required fields were missing, or the message is invalid
   * for some other reason.
   */
  class SerializationError : public std::runtime_error {
    public:
      explicit SerializationError(const char *what) : std::runtime_error(
              what) {}
  };
}

#endif //LIBLICHTENSTEIN_SERIALIZATIONERROR_H
