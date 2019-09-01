//
// Created by Tristan Seifert on 2019-08-18.
//

#include "MessageSerializer.h"
#include "SerializationError.h"

#include <string>
#include <algorithm>

#include <google/protobuf/any.h>

#include <arpa/inet.h>

#include "WireMessage.h"
#include "version.h"

#include "proto/shared/Message.pb.h"
#include "proto/shared/AuthToken.pb.h"


namespace liblichtenstein::api {
  /**
   * Serializes the given message into the byte vector specified.
   *
   * @param out Vector to hold generated wire message
   * @param payload Message to encapsulate
   */
  void MessageSerializer::serialize(std::vector<std::byte> &out,
                                    google::protobuf::Message &payload) {
    // generate the basic message
    lichtenstein::protocol::Message message;
    makeBasicMessage(payload, message);

    // serialize it into a buffer
    createWireMessage(out, message);
  }


  /**
   * Fills the field of the Lichtenstein message in to contain the payload
   * message.
   *
   * @param payload Message to encode in the API message.
   * @param message API message to work on
   */
  void
  MessageSerializer::makeBasicMessage(const google::protobuf::Message &payload,
                                      lichtenstein::protocol::Message &message) {
    // set version
    message.set_version(lichtenstein_protocol_get_version());

    // then, put message in
    auto *any = new google::protobuf::Any();
    any->PackFrom(payload);

    message.set_allocated_payload(any);
  }

  /**
   * Serializes the given message into wire format.
   *
   * @param wire Buffer to contain the wire format message
   * @param message Message to serialize
   */
  void MessageSerializer::createWireMessage(std::vector<std::byte> &wire,
                                            lichtenstein::protocol::Message &message) {
    // serialize the protobuf
    std::string protobufBytes;

    if(!message.SerializeToString(&protobufBytes)) {
      throw SerializationError("Failed to serialize message");
    }

    // get its length into a wire message header
    lichtenstein_message_t wireHeader{};

    wireHeader.length = protobufBytes.size();

    // swap fields to network byte order
    wireHeader.length = htonl(wireHeader.length);

    // copy the header into the vector
    std::byte *wireHeaderBytes = reinterpret_cast<std::byte *>(&wireHeader);
    const size_t wireHeaderSize = sizeof(wireHeader);

    std::copy(wireHeaderBytes, wireHeaderBytes + wireHeaderSize,
              std::back_inserter(wire));

    // then, copy in the protobuf itself
    std::byte *messageBytes = reinterpret_cast<std::byte *>(protobufBytes.data());
    const size_t messageBytesSize = protobufBytes.size();

    std::copy(messageBytes, messageBytes + messageBytesSize,
              std::back_inserter(wire));
  }
}