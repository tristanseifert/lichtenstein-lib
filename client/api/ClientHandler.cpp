//
// Created by Tristan Seifert on 2019-08-18.
//
#include "../version.h"

#include "ClientHandler.h"
#include "ProtocolError.h"
#include "MessageSerializer.h"

#include <glog/logging.h>

#include <cstddef>
#include <vector>
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include <functional>

#include <unistd.h>
#include <sys/utsname.h>

#include "../io/OpenSSLError.h"
#include "../io/SSLSessionClosedError.h"
#include "../io/TLSServer.h"
#include "../io/GenericServerClient.h"

#include "protocol/WireMessage.h"
#include "protocol/version.h"
#include "shared/Message.pb.h"

#include "client/GetInfo.pb.h"
#include "client/GetInfoResponse.pb.h"
#include "client/NodeInfo.pb.h"
#include "client/AdoptionStatus.pb.h"
#include "client/PerformanceInfo.pb.h"


using lichtenstein::protocol::client::GetInfo;
using lichtenstein::protocol::client::GetInfoResponse;
using lichtenstein::protocol::client::NodeInfo;
using lichtenstein::protocol::client::AdoptionStatus;
using lichtenstein::protocol::client::PerformanceInfo;

// idk
extern "C" unsigned int lichtenstein_protocol_get_version(void);


namespace liblichtenstein::api {
  /**
   * A map of type URLs to callback functions.
   *
   * Each callback function must be a member of ClientHandler. Its signature
   * accepts a single argument, the received message.
   */
  const std::unordered_map<std::string, std::function<void(
          liblichtenstein::api::ClientHandler &,
          const lichtenstein::protocol::Message &)>> handlers = {
          {"type.googleapis.com/lichtenstein.protocol.client.GetInfo", &ClientHandler::getInfo}
  };

  /**
   * Sets up a new thread to handle this client.
   *
   * @param api API to which the client connected
   * @param client Client connection
   */
  ClientHandler::ClientHandler(liblichtenstein::api::API *api,
                               std::shared_ptr<io::GenericServerClient> client)
          : api(api), client(client) {
    // set up thread
    this->thread = new std::thread(&ClientHandler::handle, this);
  }

  /**
   * Tears down the worker thread and connection.
   */
  ClientHandler::~ClientHandler() {
    this->shutdown = true;

    // try to close the client
    this->client->close();

    // wait for thread to join and delete it
    if(this->thread->joinable()) {
      this->thread->join();
    }

    delete thread;
  }


  /**
   * Worker thread entry point
   */
  void ClientHandler::handle() {
    VLOG(1) << "Got new client: " << this->client;

    // service requests as long as the API is running
    while(!this->shutdown) {
      // try to read from the client
      try {
        this->readMessage();
      }
        // an error in the TLS library happened
      catch(io::OpenSSLError &e) {
        // ignore TLS errors if we're shutting down
        if(!this->shutdown) {
          LOG(ERROR) << "TLS error reading from client: " << e.what();
        }
      }
        // if we get this exception, session was closed
      catch(io::SSLSessionClosedError &e) {
        VLOG(1) << "Connection was closed: " << e.what();
        break;
      }
        // an error decoding message
      catch(ProtocolError &e) {
        LOG(ERROR) << "Protocol error, closing connection: " << e.what();
        break;
      }
        // some other runtime error happened
      catch(std::runtime_error &e) {
        LOG(ERROR) << "Runtime error reading from client: " << e.what();
        break;
      }
    }

    // clean up client
    VLOG(1) << "Shutting down API client for client " << this->client;
    client->close();
  }

  /**
   * Attempts to wait for a message to be received.
   */
  void ClientHandler::readMessage() {
    std::vector<std::byte> received;
    int read;

    // read the wire header
    const size_t wireHeaderLen = sizeof(lichtenstein_message_t);
    read = this->client->read(received, wireHeaderLen);

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
    read = this->client->read(received, msg->length);
    VLOG(2) << "Read " << received.size() << " total bytes from client "
            << this->client;

    lichtenstein::protocol::Message message;
    this->decodeMessage(message, received);

    // we have the message now so process it
    this->processMessage(message);


  }


  /**
   * Given a wire format message, attempts to decode the protocol buffer that is
   * contained within.
   *
   * @param outMessage Protocol message into which we deserialize
   * @param buffer Buffer containing message bytes; all fields that require it
   * are swapped to host byte order at this point.
   */
  void ClientHandler::decodeMessage(lichtenstein::protocol::Message &outMessage,
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
   * Processes a received message. Its type URL is looked up in the internal
   * registry and the appropriate handler function is invoked.
   *
   * @param received Message received from the client
   */
  void
  ClientHandler::processMessage(lichtenstein::protocol::Message &received) {
    // get the type
    std::string type = received.payload().type_url();
//    LOG(INFO) << "Payload type URL: " << type;

    // do we have a handler?
    if(handlers.count(type)) {
      // if so, invoke it
      auto function = handlers.find(type)->second;
      function(*this, received);
    } else {
      LOG(WARNING) << "No handler for type " << type;
    }
  }

  /**
   * Sends a response to a previous request.
   *
   * @param response Message to respond with
   */
  void ClientHandler::sendResponse(google::protobuf::Message &response) {
    int written;

    // serialize message
    std::vector<std::byte> responseBytes;
    MessageSerializer::serialize(responseBytes, response);

    // send it
    written = this->client->write(responseBytes);

    if(written != responseBytes.size()) {
      LOG(ERROR) << "Couldn't write full message! (Wrote " << written << ", "
                 << "but total is " << responseBytes.size() << ")";
      return;
    }

    // done, I guess
    VLOG(1) << "Sent response: " << response.DebugString();
  }


  /**
   * Handles a "get info" request.
   *
   * @param received Received request
   */
  void ClientHandler::getInfo(const lichtenstein::protocol::Message &received) {
    // unpack message
    GetInfo getInfo;
    received.payload().UnpackTo(&getInfo);

    LOG(INFO) << "Get info: " << getInfo.DebugString();

    // craft response message
    GetInfoResponse response;

    // shall it include node info?
    if(getInfo.wantsnodeinfo()) {
      response.set_allocated_node(this->makeNodeInfo());
    }

    // shall it include adoption info?
    if(getInfo.wantsadoptioninfo()) {
      response.set_allocated_adoption(this->makeAdoptionStatus());
    }

    // shall it include performance info?
    if(getInfo.wantsperformanceinfo()) {
      response.set_allocated_performance(this->makePerformanceInfo());
    }

    // send it
    this->sendResponse(response);
  }

  /**
   * Gets node information into an allocated message.
   *
   * @return Allocated node info
   */
  NodeInfo *ClientHandler::makeNodeInfo() {
    int err;

    // create the node info message
    auto *node = new NodeInfo();

    // get hostname
    char hostname[256]{};
    err = gethostname(hostname, sizeof(hostname));
    PCHECK(err == 0) << "gethostname() failed";

    node->set_hostname(std::string(hostname));

    // get all the OS info via uname
    struct utsname sysnames{};
    err = uname(&sysnames);
    PCHECK(err == 0) << "uname() failed";

    std::string os = std::string(sysnames.sysname) + " " +
                     std::string(sysnames.release) + " " +
                     std::string(sysnames.version);
    node->set_os(os);

    node->set_hardware(std::string(sysnames.machine));

    // write the client version
    std::string client =
            "libLichtensteinClient " + std::string(gVERSION) + "(" +
            std::string(gVERSION_HASH) + ")";
    node->set_client(client);

    return node;
  }

  /**
   * Gets performance information into an allocated message.
   *
   * @return Allocated performance info
   */
  PerformanceInfo *ClientHandler::makePerformanceInfo() {
    auto *performance = new PerformanceInfo();

    return performance;
  }

  /**
   * Gets adoption status into an allocated message.
   *
   * @return Allocated adoption status
   */
  AdoptionStatus *ClientHandler::makeAdoptionStatus() {
    auto *adoption = new AdoptionStatus();

    return adoption;
  }


}