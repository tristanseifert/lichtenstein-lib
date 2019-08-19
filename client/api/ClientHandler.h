//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_CLIENTHANDLER_H
#define LIBLICHTENSTEIN_CLIENTHANDLER_H

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

namespace liblichtenstein::io {
  class GenericServerClient;
}

namespace liblichtenstein::api {
  class API;

  class ClientHandler {
    public:
      ClientHandler(API *api, std::shared_ptr<io::GenericServerClient> client);

      virtual ~ClientHandler();

    private:
      void handle();

      void readMessage();

      void decodeMessage(lichtenstein::protocol::Message &outMessage,
                         std::vector<std::byte> &buffer);

      void processMessage(lichtenstein::protocol::Message &received);

      void sendResponse(google::protobuf::Message &response);

    public:
      void getInfo(const lichtenstein::protocol::Message &received);

    private:
      lichtenstein::protocol::client::NodeInfo *makeNodeInfo();

      lichtenstein::protocol::client::PerformanceInfo *makePerformanceInfo();

      lichtenstein::protocol::client::AdoptionStatus *makeAdoptionStatus();

    private:
      // API that this client connected to
      API *api = nullptr;
      // client connection
      std::shared_ptr<io::GenericServerClient> client;

      // worker thread
      std::thread *thread = nullptr;
      // should we shut down?
      std::atomic_bool shutdown = false;
  };
}


#endif //LIBLICHTENSTEIN_CLIENTHANDLER_H
