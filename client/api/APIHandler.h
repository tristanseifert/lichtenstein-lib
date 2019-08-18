//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_APIHANDLER_H
#define LIBLICHTENSTEIN_APIHANDLER_H

#include <string>
#include <tuple>
#include <vector>
#include <thread>

namespace liblichtenstein::io {
  class TLSServer;

  class GenericServerClient;
}

namespace liblichtenstein::api {
  /**
   * A standalone handler for the client API.
   */
  class APIHandler {
    public:
      APIHandler(std::string &listenHost, unsigned int port,
                 std::string &certPath, std::string &certKeyPath);

      virtual ~APIHandler();

    private:
      void apiEntry();

      void apiCreateSocket();

      void apiHandleClient(std::shared_ptr<io::GenericServerClient> client);

    private:
      // worker thread for handling the client API
      std::thread *apiThread = nullptr;
      // whether the API is shutting down
      std::atomic_bool apiShutdown = false;

      // path to the API certificate
      std::string apiCertPath;
      // path to the API certificate private key
      std::string apiCertKeyPath;

      // hostname/IP on which the API listens
      std::string apiListenHost;
      // port on which the API is listening
      unsigned int apiPort = 0;

      // socket on which we're listening for the API
      int apiSocket = -1;
      // TLS server for the client API
      io::TLSServer *apiServer = nullptr;

      // a list of clients we've accepted and their threads
      std::vector<std::tuple<std::thread *, std::shared_ptr<io::GenericServerClient>>> apiClients;
  };
}


#endif //LIBLICHTENSTEIN_APIHANDLER_H
