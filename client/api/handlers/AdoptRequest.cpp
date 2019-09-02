//
// Created by Tristan Seifert on 2019-09-01.
//
#include "AdoptRequest.h"
#include "../ClientHandler.h"
#include "../HandlerFactory.h"
#include "../../Client.h"

#include "shared/Message.pb.h"
#include "client/AdoptRequest.pb.h"
#include "client/AdoptAck.pb.h"

#include <glog/logging.h>

#include <string>
#include <algorithm>

using MessageType = lichtenstein::protocol::client::AdoptRequest;
using AckMessageType = lichtenstein::protocol::client::AdoptAck;


namespace liblichtenstein::api::handler {
  /// register with the factory
  bool AdoptRequest::registered = HandlerFactory::registerClass(
          "type.googleapis.com/lichtenstein.protocol.client.AdoptRequest",
          AdoptRequest::construct);

  /**
   * Constructs a new instance of the handler.
   *
   * @param api API instance
   * @param client Client that received the request
   * @return An instance of AdoptRequest
   */
  std::unique_ptr<IRequestHandler>
  AdoptRequest::construct(API *api, ClientHandler *client) {
    return std::make_unique<AdoptRequest>(api, client);
  }


  /**
   * Handles an adopt request. This sets all the parameters into the data store
   * and then tries to verify adoption state. Since that will throw if there is
   * an error, we propagate that out which will eventually respond with an
   * error back to the server that initiated this request.
   *
   * @param received Received request
   */
  void AdoptRequest::handle(const lichtenstein::protocol::Message &received) {
    auto store = this->getClient()->getDataStore();

    // unpack message
    MessageType request;
    if(!received.payload().UnpackTo(&request)) {
      throw std::runtime_error("Failed to unpack AdoptRequest");
    }

    VLOG(1) << "Received adoption request: " << request.DebugString();

    // ensure we're not adopted
    if(this->getClient()->isAdopted()) {
      throw std::runtime_error("Node is already adopted");
    }

    // try to parse the server uuid
    if(request.serveruuid().length() != 16) {
      throw std::runtime_error("UUID must be 16 bytes");
    }

    auto uuidData = request.serveruuid().data();
    std::array<uuids::uuid::value_type, 16> uuidArray{};
    std::copy(uuidData, uuidData + 16, uuidArray.begin());

    uuids::uuid uuid(uuidArray);

    store->set("server.uuid", to_string(uuid));

    // copy the server hostname/port
    store->set("server.host", request.apiaddress());
    store->set("server.port", std::to_string(request.apiport()));

    store->set("rt.host", request.rtaddress());
    store->set("rt.port", std::to_string(request.rtport()));

    // lastly, copy the secret
    store->set("adoption.secret", request.secret());

    // then, try to do the adoption
    this->getClient()->verifyAdoption();
    store->set("adoption.valid", "1");

    // if we get here, adoption was successful, so acknowledge it
    this->adoptionSuccess();
  }

  /**
   * When adoption was successful, this is called; this acknowledges it to the
   * server and sets some internal state.
   */
  void AdoptRequest::adoptionSuccess() {
    // create ack message
    AckMessageType ack;

    ack.set_isadopted(true);

    // send message
    this->client->sendResponse(ack);
  }
}