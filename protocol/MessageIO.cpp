//
// Created by Tristan Seifert on 2019-09-02.
//
#include "MessageIO.h"

#include "version.h"
#include "MessageSerializer.h"
#include "WireMessage.h"
#include "ProtocolError.h"

#include "proto/shared/Message.pb.h"
#include "proto/shared/Error.pb.h"

#include "../io/GenericTLSClient.h"
#include "../io/GenericServerClient.h"
#include "../io/OpenSSLError.h"

#include <sstream>

#include <glog/logging.h>

using liblichtenstein::api::MessageSerializer;
using liblichtenstein::api::ProtocolError;
using liblichtenstein::io::OpenSSLError;

using lichtenstein::protocol::Error;


namespace liblichtenstein::api {
  /**
   * Creates an IO wrapper with a TLS client.
   *
   * @param client Client connection to communicate with
   */
  MessageIO::MessageIO(std::shared_ptr<io::GenericTLSClient> client) {
    this->readCallback = [client](std::vector<std::byte> &data, size_t wanted) {
      return client->read(data, wanted);
    };

    this->writeCallback = [client](const std::vector<std::byte> &data) {
      return client->write(data);
    };
  }

  /**
   * Creates an IO wrapper with a TLS server client.
   *
   * @param serverClient Server client to communicate with
   */
  MessageIO::MessageIO(std::shared_ptr<io::GenericServerClient> serverClient) {
    this->readCallback = [serverClient](std::vector<std::byte> &data,
                                        size_t wanted) {
      return serverClient->read(data, wanted);
    };

    this->writeCallback = [serverClient](const std::vector<std::byte> &data) {
      return serverClient->write(data);
    };
  }


  /**
   * Sends a response to a previous request.
   *
   * @param response Message to respond with
   */
  void MessageIO::sendMessage(google::protobuf::Message &response) {
    int written;

    // serialize message
    std::vector<std::byte> responseBytes;
    MessageSerializer::serialize(responseBytes, response);

    // send it
    written = this->writeCallback(responseBytes);

    if(written != responseBytes.size()) {
      LOG(ERROR) << "Couldn't write full message! (Wrote " << written << ", "
                 << "but total is " << responseBytes.size() << ")";
      return;
    }

    // done, I guess
    VLOG(1) << "Sent response: " << response.DebugString();
  }

  /**
   * Packages the provided C++ exception and sends it as an Error message over
   * the connection. Any errors that happen while sending the exception are
   * silently ignored.
   *
   * @param e Exception to send
   */
  void MessageIO::sendException(const std::exception &e) noexcept {
    // create error message
    Error err;

    err.set_description(e.what());

    // send it
    try {
      this->sendMessage(err);
    } catch(std::exception &e) {
      LOG(WARNING) << "Failed to send error alert: " << e.what();
    }
  }


  /**
   * Given a wire format message, attempts to decode the protocol buffer that is
   * contained within.
   *
   * @param outMessage Protocol message into which we deserialize
   * @param buffer Buffer containing message bytes; all fields that require it
   * are swapped to host byte order at this point.
   */
  void MessageIO::decodeMessage(protoMessageType &outMessage,
                                std::vector<std::byte> &buffer) {
    // get wire message struct
    auto *wire = reinterpret_cast<lichtenstein_message_t *>(buffer.data());

    // we should have at least as much in the vector as the payload size says
    if(wire->length > buffer.size()) {
      std::stringstream error;

      error << "Invalid message length (wire message indicates "
            << wire->length;
      error << " bytes of payload, but a total of " << buffer.size();
      error << " bytes were read from the client, including wire message)";

      throw ProtocolError(error.str().c_str());
    }

    // cool, we have enough data. try to decode it
    int realPayloadSize = std::min((size_t) wire->length, (buffer.size() -
                                                           sizeof(lichtenstein_message_t)));

    if(!outMessage.ParseFromArray(wire->payload, realPayloadSize)) {
      throw ProtocolError("Could not decode protobuf");
    }

    // neat, the message could be decoded. validate version
    if(outMessage.version() != lichtenstein_protocol_get_version()) {
      std::stringstream error;

      error << "Invalid protocol version (wire message is version 0x";
      error << std::hex << outMessage.version()
            << ", whereas the protocol lib is 0x";
      error << std::hex << lichtenstein_protocol_get_version() << ")";

      throw ProtocolError(error.str().c_str());
    }
  }

  /**
   * Reads a message from the client; this will either throw an exception or
   * invoke the specified success closure.
   *
   * @param success Closure to run when a valid message has been received.
   */
  void MessageIO::readMessage(
          const std::function<void(protoMessageType &)> &success) {
    std::vector<std::byte> received;
    int read;

    // read the wire header
    const size_t wireHeaderLen = sizeof(lichtenstein_message_t);
    read = this->readCallback(received, wireHeaderLen);

    if(read == 0) return;

    if(read != wireHeaderLen) {
      std::stringstream error;

      error << "Protocol error: expected to read ";
      error << wireHeaderLen << " bytes, got " << read;
      error << " bytes instead!";

      throw ProtocolError(error.str().c_str());
    }

    // byteswap all fields that need it
    void *data = received.data();
    auto *msg = reinterpret_cast<lichtenstein_message_t *>(data);

    msg->length = ntohl(msg->length);

    VLOG(2) << "Message contains " << msg->length << " more bytes";

    // read the rest of the payload now (size checking happens during decode)
    read = this->readCallback(received, msg->length);
    VLOG(2) << "Read " << received.size() << " total bytes";

    lichtenstein::protocol::Message message;
    this->decodeMessage(message, received);

    // message is valid, so run callback
    success(message);
  }
}