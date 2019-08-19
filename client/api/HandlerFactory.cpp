//
// Created by Tristan Seifert on 2019-08-19.
//

#include "HandlerFactory.h"

#include <glog/logging.h>

#include <iomanip>
#include <sstream>
#include <mutex>


namespace liblichtenstein::api {
  /// holds registered classes
  std::map<std::string, HandlerFactory::createMethod> *HandlerFactory::registrations = nullptr;


  /**
   * Registers a class with the factory.
   *
   * @param name Type name of the class' protobuf message
   * @param funcCreate Constructor of the class
   * @return Whether the registration was added
   */
  bool HandlerFactory::registerClass(const std::string type,
                                     createMethod funcCreate) {
    // keep a lock
    static std::mutex registerLock;
    std::lock_guard guard(registerLock);

    // allocate map if needed
    if(registrations == nullptr) {
      registrations = new std::map<std::string, createMethod>();
    }

    // register if we haven't already got this registration
    if(auto it = registrations->find(type); it == registrations->end()) {
      registrations->insert(std::make_pair(type, funcCreate));
//      registrations[type] = funcCreate;
      return true;
    }

    // someone already registered this class
    LOG(ERROR) << "Attempt to register handler for " << type
               << ", which already has a registration";
    return false;
  }

  /**
   * Instantiates a handler for the given message type.
   *
   * @param type Type name of the protobuf message
   * @param api API instance associated with this message
   * @param client Client handler that received the request
   * @return An instance of a handler or nullptr
   */
  std::unique_ptr<IRequestHandler>
  HandlerFactory::create(const std::string &type, API *api,
                         ClientHandler *client) {
    // try to find a handler for this name
    if(auto it = registrations->find(type); it != registrations->end()) {
      return it->second(api, client);
    }

    // no such handler :(
    return nullptr;
  }

  /**
   * Dumps all registered functions
   */
  void HandlerFactory::dump() {
    std::stringstream str;

    for(auto const &[key, func] : *registrations) {
      str << std::setw(40) << std::setfill(' ') << key << std::setw(0);
      str << func << std::endl;
    }

    LOG(INFO) << "Registered handlers: " << std::endl << str.str();
  }
}