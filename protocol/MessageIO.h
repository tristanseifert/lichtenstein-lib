//
// Created by Tristan Seifert on 2019-09-02.
//

#ifndef LIBLICHTENSTEIN_IO_MESSAGEIO_H
#define LIBLICHTENSTEIN_IO_MESSAGEIO_H

#include <functional>
#include <cstddef>
#include <vector>

#include <google/protobuf/message.h>

namespace lichtenstein::protocol {
  class Message;
}

namespace liblichtenstein::io {
  class GenericTLSClient;

  class GenericServerClient;
}

namespace liblichtenstein::api {
  /**
   * Provides a thin wrapper around TLS servers/clients, hiding the underlying
   * wire protocol and exposing a few convenient methods to send/receive the
   * Protobuf classes that make up the protocol.
   */
  class MessageIO {
      using protoMessageType = lichtenstein::protocol::Message;

    public:
      MessageIO() = delete;

      MessageIO(std::shared_ptr<io::GenericTLSClient> client);

      MessageIO(std::shared_ptr<io::GenericServerClient> serverClient);

    public:
      void sendMessage(google::protobuf::Message &response);

      void decodeMessage(protoMessageType &outMessage,
                         std::vector<std::byte> &buffer);

      void readMessage(const std::function<void(protoMessageType &)> &success);

    private:
      // read function
      std::function<size_t(std::vector<std::byte> &, size_t)> readCallback;
      // write function
      std::function<size_t(const std::vector<std::byte> &)> writeCallback;
  };
}


#endif //LIBLICHTENSTEIN_IO_MESSAGEIO_H
