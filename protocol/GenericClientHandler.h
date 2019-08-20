//
// Created by Tristan Seifert on 2019-08-20.
//

#ifndef LIBLICHTENSTEIN_GENERICCLIENTHANDLER_H
#define LIBLICHTENSTEIN_GENERICCLIENTHANDLER_H

#include <memory>
#include <functional>

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
      void sendResponse(google::protobuf::Message &response);

    protected:
      void readMessage(const std::function<void(protoMessageType &)> &success);

      void decodeMessage(protoMessageType &outMessage,
                         std::vector<std::byte> &buffer);

    protected:
      // client connection
      std::shared_ptr<clientType> client;
  };
}


#endif //LIBLICHTENSTEIN_GENERICCLIENTHANDLER_H
