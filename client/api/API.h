//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_API_H
#define LIBLICHTENSTEIN_API_H

#include <string>
#include <vector>
#include <thread>

namespace liblichtenstein::io {
  class TLSServer;

  class GenericServerClient;
}

namespace liblichtenstein {
  class Client;
}

namespace liblichtenstein::api {
  class ClientHandler;

  /**
   * A standalone handler for the client API.
   */
  class API {
      friend class ClientHandler;

    public:
      API(std::string &listenHost, unsigned int port,
          std::string &certPath, std::string &certKeyPath);

      API(std::string &listenHost, unsigned int port,
          std::string &certPath, std::string &certKeyPath, Client *client)
              : API(listenHost, port, certPath, certKeyPath) {
        this->client = client;
      };

      virtual ~API();

    private:
      void apiEntry();

      void apiCreateSocket();

    private:
      // worker thread for handling the client API
      std::thread *thread = nullptr;
      // whether the API is shutting down
      std::atomic_bool shutdown = false;

      // path to the API certificate
      std::string certPath;
      // path to the API certificate private key
      std::string certKeyPath;

      // hostname/IP on which the API listens
      std::string listenAddress;
      // port on which the API is listening
      unsigned int listenPort = 0;

      // socket on which we're listening for the API
      int socket = -1;
      // TLS server for the client API
      io::TLSServer *tlsServer = nullptr;

      // a list of clients we've accepted and their threads
      std::vector<std::shared_ptr<ClientHandler>> clients;

      // client state machine
      Client *client = nullptr;
  };
}


#endif //LIBLICHTENSTEIN_API_H
