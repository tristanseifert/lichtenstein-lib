//
// Created by Tristan Seifert on 2019-08-31.
//
#include "RealtimeClient.h"
#include "Client.h"
#include "IClientDataStore.h"
#include "protocol/HmacChallengeHandler.h"

#include "io/OpenSSLError.h"
#include "io/DTLSClient.h"

#include "protocol/version.h"
#include "protocol/MessageSerializer.h"
#include "protocol/WireMessage.h"
#include "protocol/ProtocolError.h"

#include "shared/Message.pb.h"

#include <glog/logging.h>

#include <google/protobuf/message.h>


using DTLSClient = liblichtenstein::io::DTLSClient;
using SSLError = liblichtenstein::io::OpenSSLError;

using liblichtenstein::api::HmacChallengeHandler;

using liblichtenstein::api::MessageSerializer;
using liblichtenstein::api::ProtocolError;


namespace liblichtenstein::api {
  /**
   * Instantiates the realtime client.
   *
   * @param client Client instance on which the connection stems from
   * @param host Host to connect to
   * @param port Port to connect to
   */
  RealtimeClient::RealtimeClient(Client *client, const std::string &host,
                                 const unsigned int port) : client(client) {
    // create the DTLS client
    try {
      this->dtlsClient = std::make_shared<DTLSClient>(host, port);
    } catch(SSLError &e) {
      LOG(ERROR) << "SSL error while creating DTLS client: " << e.what();
      throw e;
    } catch(std::system_error &e) {
      LOG(ERROR) << "System error while creating DTLS client: " << e.what();
      throw e;
    }

    // create the worker thread
    this->thread = std::make_unique<std::thread>(&RealtimeClient::threadEntry,
                                                 this);
  }

  /**
   * Cleans up the resources used by the realtime client.
   */
  RealtimeClient::~RealtimeClient() {
    // mark shutdown
    this->shutdown = true;

    // close connection
    this->dtlsClient->close();
    this->dtlsClient = nullptr;

    // stop thread
    if(this->thread->joinable()) {
      this->thread->join();
    }

    this->thread = nullptr;
  }


  /**
   * Entry point of the worker thread
   */
  void RealtimeClient::threadEntry() {
    // attempt to authenticate
    auto secret = this->client->dataStore->get("adoption.token");

    HmacChallengeHandler handler(this->dtlsClient, secret.value(),
                                 this->client->nodeUuid);

    try {
      handler.authenticate();

      VLOG(1) << "Successfully authenticated realtime client";
    } catch(std::exception &e) {
      LOG(ERROR) << "Failed to authenticate realtime client: " << e.what();

      this->shutdown = true;
    }


    // wait for a message
    while(!this->shutdown) {
      // wait for a message
      this->readMessage([this](protoMessageType &message) {

      });
    }

    // clean up
    VLOG(1) << "Realtime client shutting down";

    if(this->dtlsClient) {
      this->dtlsClient->close();
      this->dtlsClient = nullptr;
    }
  }


  /**
   * Sends a response to a previous request.
   *
   * @param response Message to respond with
   */
  void RealtimeClient::sendMessage(google::protobuf::Message &response) {
    int written;

    // serialize message
    std::vector<std::byte> responseBytes;
    MessageSerializer::serialize(responseBytes, response);

    // send it
    written = this->dtlsClient->write(responseBytes);

    if(written != responseBytes.size()) {
      LOG(ERROR) << "Couldn't write full message! (Wrote " << written << ", "
                 << "but total is " << responseBytes.size() << ")";
      return;
    }

    // done, I guess
    VLOG(1) << "Sent response: " << response.DebugString();
  }


  /**
   * Given a wire format message, attempts to decode the protocol buffer that is
   * contained within.
   *
   * @param outMessage Protocol message into which we deserialize
   * @param buffer Buffer containing message bytes; all fields that require it
   * are swapped to host byte order at this point.
   */
  void RealtimeClient::decodeMessage(protoMessageType &outMessage,
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
  void RealtimeClient::readMessage(
          const std::function<void(protoMessageType &)> &success) {
    std::vector<std::byte> received;
    int read;

    // read the wire header
    const size_t wireHeaderLen = sizeof(lichtenstein_message_t);
    read = this->dtlsClient->read(received, wireHeaderLen);

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
    read = this->dtlsClient->read(received, msg->length);
    VLOG(2) << "Read " << received.size() << " total bytes from client "
            << this->client;

    lichtenstein::protocol::Message message;
    this->decodeMessage(message, received);

    // message is valid, so run callback
    success(message);
  }
}