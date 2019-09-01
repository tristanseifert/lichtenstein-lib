//
// Created by Tristan Seifert on 2019-08-24.
//

#ifndef LIBLICHTENSTEIN_BASICFILEDATASTORE_H
#define LIBLICHTENSTEIN_BASICFILEDATASTORE_H

#include "../../client/IClientDataStore.h"

#include <string>
#include <map>

/**
 * Stores the key/value store in a file on disk.
 */
class BasicFileDataStore : public liblichtenstein::IClientDataStore {
  public:
    explicit BasicFileDataStore(const std::string &path);

  public:
    [[nodiscard]] bool hasKey(const KeyType &key) const override {
      return (this->data.count(key) == 1);
    }

    void set(const KeyType &key, ValueType value) override {
      this->data[key] = value;
      this->write();
    }

    [[nodiscard]] std::optional<std::string>
    get(const KeyType &key) const override {
      if(this->hasKey(key)) {
        return this->data.find(key)->second;
      } else {
        return std::nullopt;
      }
    }

  private:
    void load();

    void write();

  private:
    // path to file
    std::string path;

    // actual store
    std::map<KeyType, ValueType> data;
};


#endif //LIBLICHTENSTEIN_BASICFILEDATASTORE_H
