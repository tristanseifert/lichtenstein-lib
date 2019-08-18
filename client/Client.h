//
// Created by Tristan Seifert on 2019-08-17.
//

#ifndef LIBLICHTENSTEIN_CLIENT_H
#define LIBLICHTENSTEIN_CLIENT_H

#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <array>

namespace liblichtenstein {
  namespace io {
    class DTLSClient;

    class TLSServer;
  }

  namespace mdns {
    class Service;
  }

  /**
   * This class implements a full lichtenstein network client. It advertises
   * itself over the network when started, and handles all network communication
   * transparently in a background thread.
   *
   * All that's needed is some information regarding the client's config, then
   * it can be started. This information can be changed at a later time and
   * reloaded, or the client can be stopped entirely.
   */
  class Client {
    public:
      Client(std::string listenIp, unsigned int apiPort);

      virtual ~Client();

    public:
      void start();

      void stop();

      void reload();

    private:
      void checkConfig();

      void stopRt();

      void stopApi();

    private:
      // node UUID
      std::array<uint8_t, 16> nodeUuid{};

      // MDNS client used to advertise the client API
      mdns::Service *clientService = nullptr;

      // worker thread for handling the realtime protocol
      std::thread *rtThread = nullptr;
      // whether the real time client is shutting down
      std::atomic_bool rtShutdown = false;

      // DTLS client to realtime API
      io::DTLSClient *rtClient = nullptr;


      // worker thread for handling the client API
      std::thread *apiThread = nullptr;
      // whether the API is shutting down
      std::atomic_bool apiShutdown = false;

      // hostname/IP on which the API listens
      std::string apiListenHost;
      // port on which the API is listening
      unsigned int apiPort = 0;

      // socket on which we're listening for the API
      int apiSocket = -1;
      // TLS server for the client API
      io::TLSServer *apiServer = nullptr;
  };
}


#endif //LIBLICHTENSTEIN_CLIENT_H
