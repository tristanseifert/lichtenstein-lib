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
#include "protocol/MessageIO.h"

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

      this->io = std::make_shared<MessageIO>(this->dtlsClient);
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
    if(this->dtlsClient) {
      this->dtlsClient->close();
      this->dtlsClient = nullptr;
    }

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
    auto secret = this->client->dataStore->get("adoption.secret");

    HmacChallengeHandler handler(this->io, secret.value(),
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
      try {
        // wait for a message
        this->io->readMessage([this](protoMessageType &message) {
          // TODO: process message
          VLOG(1) << "Received realtime message: " << message.DebugString();
        });
      } catch(SSLError &e) {
        LOG(WARNING) << "SSL error on realtime client: " << e.what();
        goto fatalError;
      } catch(std::system_error &e) {
        LOG(WARNING) << "System error in realtime client: " << e.what();
        goto fatalError;
      }
        // protocol errors may be recoverable
      catch(ProtocolError &e) {
        LOG(WARNING) << "Protocol error in realtime client: " << e.what();
        this->io->sendException(e);
      }
        // runtime errors may be recoverable
      catch(std::runtime_error &e) {
        LOG(WARNING) << "Runtime error in realtime client: " << e.what();
        this->io->sendException(e);
      }
    }

    // clean up
    shutdown:;
    VLOG(1) << "Realtime client shutting down";

    if(this->dtlsClient) {
      this->dtlsClient->close();
      this->dtlsClient = nullptr;
    }

    return;

    // handle an error that requires the client to be closed
    fatalError:;
    LOG(ERROR) << "Fatal error in handling realtime client";

    goto shutdown;
  }
}