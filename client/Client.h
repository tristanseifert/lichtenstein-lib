//
// Created by Tristan Seifert on 2019-08-17.
//

#ifndef LIBLICHTENSTEIN_CLIENT_H
#define LIBLICHTENSTEIN_CLIENT_H

#include "IClientDataStore.h"

#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <array>
#include <mutex>
#include <condition_variable>
#include <tuple>
#include <vector>
#include <memory>

#include <uuid.h>


namespace liblichtenstein {
  namespace io {
    class DTLSClient;

    class TLSClient;
    class TLSServer;

    class GenericServerClient;
  }

  namespace api {
    class API;

    class RealtimeClient;

    namespace handler {
      class AdoptRequest;
    }
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
      friend class api::RealtimeClient;

      friend class api::handler::AdoptRequest;

    private:
      typedef enum {
        START,
        IDLE,
        SHUTDOWN,

        VERIFY_ADOPT,
        START_RT,
      } StateMachineState;

    public:
      Client(const std::string listenIp, unsigned int apiPort,
             const std::string certPath, const std::string certKeyPath);

      virtual ~Client();

    public:
      void start();

      void stop();

      void reload();

    public:
      void setNodeUuid(const uuids::uuid &newNodeUuid) {
        this->nodeUuid = newNodeUuid;
      }

      void setNodeUuid(const std::array<uint8_t, 16> &newNodeUuidBytes) {
        this->nodeUuid = uuids::uuid(newNodeUuidBytes);
      }

      void setDataStore(std::shared_ptr<IClientDataStore> store) {
        this->dataStore = store;
      }

    public:
      bool isAdopted() const {
        auto result = this->dataStore->get("adoption.valid");

        return (result.has_value() && (result == "1"));
      }

      uuids::uuid getNodeUuid() const {
        return this->nodeUuid;
      }

      std::shared_ptr<IClientDataStore> getDataStore() {
        return this->dataStore;
      }

    private:
      void checkConfig();

      void startRt();
      void stopRt();

    private:
      void stateMachine();

      void setNextState(StateMachineState next);

    private:
      /// attempt to verify adoption state (same as VERIFY_ADOPT state)
      void verifyAdoption() {
        this->attemptServerConnection();
        this->setNextState(START_RT);
      }

      void attemptServerConnection();

      bool validateAdoptionToken(const std::string &token);

    private:
      // node UUID
      uuids::uuid nodeUuid;

    private:
      // overall client state machine thread
      std::unique_ptr<std::thread> stateMachineThread;
      // whether the state machine should shut down
      std::atomic_bool stateMachineShutdown = false;

      StateMachineState stateMachineCurrent = START;

    private:
      // MDNS client used to advertise the client API
      std::unique_ptr<mdns::Service> clientService;

    private:
      // realtime client
      std::unique_ptr<api::RealtimeClient> rtClient;

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

    private:
      // TLS client to server API
      std::shared_ptr<io::TLSClient> serverApiClient;

    private:
      // data store containing our internal state
      std::shared_ptr<IClientDataStore> dataStore;
  };
}


#endif //LIBLICHTENSTEIN_CLIENT_H
