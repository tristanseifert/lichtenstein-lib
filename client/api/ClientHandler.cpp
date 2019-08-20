//
// Created by Tristan Seifert on 2019-08-18.
//
#include "../version.h"

#include "ClientHandler.h"
#include "HandlerFactory.h"
#include "protocol/ProtocolError.h"

#include <glog/logging.h>

#include <cstddef>
#include <vector>
#include <sstream>
#include <algorithm>
#include <functional>

#include "io/OpenSSLError.h"
#include "io/SSLSessionClosedError.h"
#include "io/GenericServerClient.h"

#include "shared/Message.pb.h"

// idk
extern "C" unsigned int lichtenstein_protocol_get_version(void);


namespace liblichtenstein::api {
  /**
   * Sets up a new thread to handle this client.
   *
   * @param api API to which the client connected
   * @param client Client connection
   */
  ClientHandler::ClientHandler(liblichtenstein::api::API *api,
                               std::shared_ptr<io::GenericServerClient> client)
          : GenericClientHandler(client), api(api) {
    // set up thread
    this->thread = new std::thread(&ClientHandler::handle, this);
  }

  /**
   * Tears down the worker thread and connection.
   */
  ClientHandler::~ClientHandler() {
    this->shutdown = true;

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
        this->readMessage([this](protoMessageType &message) {
          this->processMessage(message);
        });
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
   * Processes a received message. Its type URL is looked up in the internal
   * registry and the appropriate handler function is invoked.
   *
   * @param received Message received from the client
   */
  void
  ClientHandler::processMessage(lichtenstein::protocol::Message &received) {
    // get the type and try to allocate a handler
    std::string type = received.payload().type_url();

    auto handler = HandlerFactory::create(type, this->api, this);

    // invoke handler function
    if(handler) {
      handler->handle(received);
    }
      // otherwise, treat this as an error and close connection
    else {
      std::stringstream error;

      HandlerFactory::dump();

      error << "Received message of unknown type " << type;
      throw ProtocolError(error.str().c_str());
    }
  }
}