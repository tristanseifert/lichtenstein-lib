//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_MESSAGESERIALIZER_H
#define LIBLICHTENSTEIN_MESSAGESERIALIZER_H

#include <cstddef>
#include <vector>
#include <google/protobuf/message.h>

namespace lichtenstein::protocol {
  class Message;
}

namespace liblichtenstein::api {
  /**
   * This class provides some static helpers to serialize arbitrary messages
   * into a byte string.
   */
  class MessageSerializer {
    public:
      MessageSerializer() = delete;

      ~MessageSerializer() = delete;

    public:
      static void serialize(std::vector<std::byte> &out,
                            google::protobuf::Message &payload);

      static void serializeWithAuth(std::vector<std::byte> &out,
                                    const std::vector<std::byte> &authToken,
                                    google::protobuf::Message &payload);

    private:
      static void makeBasicMessage(const google::protobuf::Message &payload,
                                   lichtenstein::protocol::Message &message);

      static void createWireMessage(std::vector<std::byte> &wire,
                                    lichtenstein::protocol::Message &message);
  };
}


#endif //LIBLICHTENSTEIN_MESSAGESERIALIZER_H
