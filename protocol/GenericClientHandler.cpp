//
// Created by Tristan Seifert on 2019-08-20.
//
#include "GenericClientHandler.h"
#include "MessageSerializer.h"
#include "WireMessage.h"
#include "ProtocolError.h"
#include "version.h"

#include "proto/shared/Message.pb.h"
#include "proto/shared/Error.pb.h"

#include "../io/GenericServerClient.h"

#include <glog/logging.h>

#include <google/protobuf/message.h>

using lichtenstein::protocol::Error;


namespace liblichtenstein::api {
  /**
   * Creates a generic client handler.
   *
   * @param client Client that connected
   */
  GenericClientHandler::GenericClientHandler(std::shared_ptr<clientType> client)
          : client(client) {
    this->io = std::make_shared<MessageIO>(client);
  }

  /**
   * Cleans up the client connection when deallocating.
   */
  GenericClientHandler::~GenericClientHandler() {
    // try to close the client
    this->client->close();
  }
}