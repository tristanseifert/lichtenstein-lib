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
#include <mutex>
#include <condition_variable>
#include <tuple>
#include <vector>
#include "api/API.h"


namespace liblichtenstein {
  namespace io {
    class DTLSClient;
    class TLSServer;

    class GenericServerClient;
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
    private:
      typedef enum {
        START,
        IDLE,
        SHUTDOWN,
      } StateMachineState;

    public:
      Client(const std::string listenIp, unsigned int apiPort,
             const std::string certPath, const std::string certKeyPath);

      virtual ~Client();

    public:
      void start();

      void stop();

      void reload();

    private:
      void checkConfig();

      void stopRt();

    private:
      void stateMachine();

      void setNextState(StateMachineState next);

    private:
      // node UUID
      std::array<uint8_t, 16> nodeUuid{};

    private:
      // overall client state machine thread
      std::thread *stateMachineThread = nullptr;
      // whether the state machine should shut down
      std::atomic_bool stateMachineShutdown = false;

      StateMachineState stateMachineCurrent = START;

    private:
      // MDNS client used to advertise the client API
      mdns::Service *clientService = nullptr;

    private:
      // worker thread for handling the realtime protocol
      std::thread *rtThread = nullptr;
      // whether the real time client is shutting down
      std::atomic_bool rtShutdown = false;

      // DTLS client to realtime API
      io::DTLSClient *rtClient = nullptr;

      // mutex for condition variable
      std::mutex stateMachineCvLock;
      // condition variable
      std::condition_variable stateMachineCv;
      // wake up the state machine (can only be written to true by others)
      std::atomic_bool stateMachineWakeUp = false;

    private:
      // handles all API stuff
      api::API *apiHandler = nullptr;

      // host the API listens on
      std::string apiHost;
      // port the API listens on
      unsigned int apiPort = 0;

      // path to API certificate
      std::string apiCertPath;
      // path to API certificate private key
      std::string apiCertKeyPath;
  };
}


#endif //LIBLICHTENSTEIN_CLIENT_H
