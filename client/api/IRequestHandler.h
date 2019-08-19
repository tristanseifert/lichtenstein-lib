//
// Created by Tristan Seifert on 2019-08-19.
//

#ifndef LIBLICHTENSTEIN_IREQUESTHANDLER_H
#define LIBLICHTENSTEIN_IREQUESTHANDLER_H

namespace lichtenstein::protocol {
  class Message;
}

namespace liblichtenstein::api {
  class API;

  class ClientHandler;

  /**
   * Provides the interface implemented by all request handlers.
   */
  class IRequestHandler {
    public:
      IRequestHandler() = delete;

      IRequestHandler(API *api, ClientHandler *client) : api(api),
                                                         client(client) {}

      virtual ~IRequestHandler() = default;

    public:
      virtual void handle(const lichtenstein::protocol::Message &received) = 0;

    protected:
      // API on which this request was made
      API *api = nullptr;
      // client handler that received this request
      ClientHandler *client = nullptr;
  };
}

#endif //LIBLICHTENSTEIN_IREQUESTHANDLER_H
