//
// Created by Tristan Seifert on 2019-08-20.
//

#ifndef LIBLICHTENSTEIN_GENERICCLIENTHANDLER_H
#define LIBLICHTENSTEIN_GENERICCLIENTHANDLER_H

#include "MessageIO.h"

#include <memory>
#include <functional>
#include <atomic>
#include <exception>

namespace google::protobuf {
  class Message;
}
namespace lichtenstein::protocol {
  class Message;
}

namespace liblichtenstein::io {
  class GenericServerClient;
}


namespace liblichtenstein::api {
  /**
   * Implements a generic client handler.
   */
  class GenericClientHandler {
    protected:
      using clientType = liblichtenstein::io::GenericServerClient;
      using protoMessageType = lichtenstein::protocol::Message;

    public:
      GenericClientHandler() = delete;
      explicit GenericClientHandler(std::shared_ptr<clientType> client);

      virtual ~GenericClientHandler();

    public:
      /// sends a response to the client (used by handlers)
      void sendResponse(google::protobuf::Message &response) {
        this->io->sendMessage(response);
      }

      /// shuts down the client
      virtual void close() {
        this->shutdown = true;
      }

      /// processes a generic exception into an error message
      virtual void sendException(const std::exception &e) noexcept;

    protected:
      void readMessage(const std::function<void(protoMessageType &)> &success) {
        this->io->readMessage(success);
      }

    protected:
      // client connection
      std::shared_ptr<clientType> client;
      // message IO instance used
      std::shared_ptr<MessageIO> io;

      // whether the client has been shut down
      std::atomic_bool shutdown = false;
  };
}


#endif //LIBLICHTENSTEIN_GENERICCLIENTHANDLER_H
