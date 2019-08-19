//
// Created by Tristan Seifert on 2019-08-19.
//

#ifndef LIBLICHTENSTEIN_GETINFOREQ_H
#define LIBLICHTENSTEIN_GETINFOREQ_H

#include "../IRequestHandler.h"

#include <memory>

namespace lichtenstein::protocol {
  class Message;

  namespace client {
    class NodeInfo;

    class PerformanceInfo;

    class AdoptionStatus;
  }
}

namespace liblichtenstein::api::handler {
  /**
   * Handles the "get info" request.
   */
  class GetInfoReq : public IRequestHandler {
    public:
      GetInfoReq(API *api, ClientHandler *client) : IRequestHandler(api,
                                                                    client) {};

      virtual void handle(const lichtenstein::protocol::Message &received);

    private:
      static std::unique_ptr<IRequestHandler>
      construct(API *api, ClientHandler *client);

    private:
      lichtenstein::protocol::client::NodeInfo *makeNodeInfo();

      lichtenstein::protocol::client::PerformanceInfo *makePerformanceInfo();

      lichtenstein::protocol::client::AdoptionStatus *makeAdoptionStatus();

    private:
      static bool registered;
  };
}


#endif //LIBLICHTENSTEIN_GETINFOREQ_H
