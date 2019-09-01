//
// Created by Tristan Seifert on 2019-08-19.
//

#include "GetInfoReq.h"
#include "../ClientHandler.h"
#include "../HandlerFactory.h"
#include "../../Client.h"

#include <glog/logging.h>

#include <string>

#include <unistd.h>
#include <sys/utsname.h>

#include "shared/Message.pb.h"
#include "client/GetInfo.pb.h"
#include "client/GetInfoResponse.pb.h"
#include "client/NodeInfo.pb.h"
#include "client/AdoptionStatus.pb.h"
#include "client/PerformanceInfo.pb.h"

#include "../../version.h"


using lichtenstein::protocol::client::GetInfo;
using lichtenstein::protocol::client::GetInfoResponse;
using lichtenstein::protocol::client::NodeInfo;
using lichtenstein::protocol::client::AdoptionStatus;
using lichtenstein::protocol::client::PerformanceInfo;

namespace liblichtenstein::api::handler {
  /// register with the factory
  bool GetInfoReq::registered = HandlerFactory::registerClass(
          "type.googleapis.com/lichtenstein.protocol.client.GetInfo",
          GetInfoReq::construct);

  /**
   * Constructs a new instance of the handler.
   *
   * @param api API instance
   * @param client Client that received
   * @return
   */
  std::unique_ptr<IRequestHandler>
  GetInfoReq::construct(API *api, ClientHandler *client) {
    return std::make_unique<GetInfoReq>(api, client);
  }


  /**
   * Handles a "get info" request.
   *
   * @param received Received request
   */
  void GetInfoReq::handle(const lichtenstein::protocol::Message &received) {
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
    this->client->sendResponse(response);
  }


  /**
   * Gets node information into an allocated message.
   *
   * @return Allocated node info
   */
  NodeInfo *GetInfoReq::makeNodeInfo() {
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

    // extract uuid
    auto uuidBytes = this->getClient()->getNodeUuid().as_bytes();
    node->set_uuid(uuidBytes.data(), uuidBytes.size());

    return node;
  }

  /**
   * Gets performance information into an allocated message.
   *
   * @return Allocated performance info
   */
  PerformanceInfo *GetInfoReq::makePerformanceInfo() {
    auto *performance = new PerformanceInfo();

    return performance;
  }

  /**
   * Gets adoption status into an allocated message.
   *
   * @return Allocated adoption status
   */
  AdoptionStatus *GetInfoReq::makeAdoptionStatus() {
    auto *adoption = new AdoptionStatus();

    // are we adopted?
    adoption->set_isadopted(this->getClient()->isAdopted());

    return adoption;
  }
}