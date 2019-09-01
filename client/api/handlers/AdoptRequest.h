//
// Created by Tristan Seifert on 2019-09-01.
//

#ifndef LIBLICHTENSTEIN_API_HANDLERS_ADOPTREQUEST_H
#define LIBLICHTENSTEIN_API_HANDLERS_ADOPTREQUEST_H

#include "../IRequestHandler.h"

#include <memory>

namespace lichtenstein::protocol {
  class Message;
}


namespace liblichtenstein::api::handler {
  /**
   * Handles adoption requests from servers. If the node is not already adopted,
   * we attempt to connect to the server with the information provided, and then
   * complete adoption.
   *
   * Otherwise, if the node is already adopted, an error is returned. Even if
   * the node is not adopted, it can respond with an error if any step during
   * adoption (such as connecting to the server) fails.
   */
  class AdoptRequest : public IRequestHandler {
    public:
      AdoptRequest(API *api, ClientHandler *client) : IRequestHandler(api,
                                                                      client) {};

      void handle(const lichtenstein::protocol::Message &received) override;

    private:
      void adoptionSuccess();

    private:
      static std::unique_ptr<IRequestHandler>
      construct(API *api, ClientHandler *client);

    private:
      static bool registered;
  };
}


#endif //LIBLICHTENSTEIN_API_HANDLERS_ADOPTREQUEST_H
