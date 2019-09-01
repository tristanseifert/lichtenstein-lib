//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_CLIENTHANDLER_H
#define LIBLICHTENSTEIN_CLIENTHANDLER_H

#include "protocol/GenericClientHandler.h"

#include <atomic>
#include <thread>
#include <memory>
#include <cstddef>
#include <google/protobuf/message.h>

namespace lichtenstein::protocol {
  class Message;

  namespace client {
    class NodeInfo;

    class PerformanceInfo;

    class AdoptionStatus;
  }
}

namespace liblichtenstein {
  class Client;
}

namespace liblichtenstein::io {
  class GenericServerClient;
}

namespace liblichtenstein::api {
  class API;

  class IRequestHandler;

  class ClientHandler : public GenericClientHandler {
      friend class Client;

      friend class IRequestHandler;

    public:
      ClientHandler(API *api, std::shared_ptr<io::GenericServerClient> client);

      ~ClientHandler() override;

    protected:
      Client *getClient();

    private:
      void handle();

      void processMessage(lichtenstein::protocol::Message &received);

    private:
      // API that this client connected to
      API *api = nullptr;

      // worker thread
      std::thread *thread = nullptr;
      // should we shut down?
      std::atomic_bool shutdown = false;
  };
}


#endif //LIBLICHTENSTEIN_CLIENTHANDLER_H
