//
// Created by Tristan Seifert on 2019-08-24.
//
#include "BasicFileDataStore.h"

#include <glog/logging.h>

#include <fstream>

/**
 * Loads the data store from disk.
 *
 * @param path Path of the data store
 */
BasicFileDataStore::BasicFileDataStore(const std::string &path) : path(path) {
  this->load();
}

/**
 * Loads the data store from disk.
 */
void BasicFileDataStore::load() {
  // try to open stream
  std::ifstream stream(this->path);

  if(stream.fail()) {
    LOG(WARNING) << "Could not read data store from: " << this->path;
    return;
  }

  // read line by line
  while(!stream.eof()) {
    std::string key, value;

    stream >> key >> value;

    this->data[key] = value;
  }
}

/**
 * Writes the data store to disk.
 */
void BasicFileDataStore::write() {
  // write it to file
  std::ofstream stream(this->path);

  for(auto &[key, value] : this->data) {
    stream << key << ' ' << value << std::endl;
  }
}
