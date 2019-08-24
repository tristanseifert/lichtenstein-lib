//
// Created by Tristan Seifert on 2019-08-24.
//

#ifndef LIBLICHTENSTEIN_ICLIENTDATASTORE_H
#define LIBLICHTENSTEIN_ICLIENTDATASTORE_H

#include <string>
#include <optional>

namespace liblichtenstein {
  /**
   * Interface used by the Client class to handle some internal key/value data
   * that it uses for storing state. The meaning of this data is opaque to the
   * class implementing this interface.
   *
   * Keys and values are both strings. Keys should be persisted between launches
   * of the client somehow.
   *
   * The client may call functions in this interface from any thread in the
   * application, so if thread safety is required, the data store should
   * implement it.
   */
  class IClientDataStore {
    public:
      using KeyType = std::string;
      using ValueType = std::string;

    public:
      virtual bool hasKey(const KeyType &key) const = 0;

      virtual void set(const KeyType &key, ValueType value) = 0;

      virtual std::optional<std::string> get(const KeyType &key) const = 0;
  };
}

#endif //LIBLICHTENSTEIN_ICLIENTDATASTORE_H
