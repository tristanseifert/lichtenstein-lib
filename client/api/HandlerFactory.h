//
// Created by Tristan Seifert on 2019-08-19.
//

#ifndef LIBLICHTENSTEIN_HANDLERFACTORY_H
#define LIBLICHTENSTEIN_HANDLERFACTORY_H

#include "IRequestHandler.h"

#include <memory>
#include <string>
#include <map>

namespace liblichtenstein::api {
  class API;

  class ClientHandler;

  /**
   * The handler factory contains a registry of all API handlers
   */
  class HandlerFactory {
    public:
      using createMethod = std::unique_ptr<IRequestHandler>(*)(API *,
                                                               ClientHandler *);

    public:
      HandlerFactory() = delete;

    public:
      static bool
      registerClass(const std::string type, createMethod funcCreate);

      static std::unique_ptr<IRequestHandler>
      create(const std::string &type, API *api, ClientHandler *client);

      static void dump();

    private:
      static std::map<std::string, createMethod> *registrations;
  };
};


#endif //LIBLICHTENSTEIN_HANDLERFACTORY_H
