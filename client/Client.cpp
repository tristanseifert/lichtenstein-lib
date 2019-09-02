//
// Created by Tristan Seifert on 2019-08-17.
//
#include "Client.h"
#include "IClientDataStore.h"
#include "RealtimeClient.h"

#include <glog/logging.h>

#include <memory>
#include <utility>

#include "io/mdns/Service.h"

#include "api/API.h"
#include "io/TLSClient.h"
#include "io/OpenSSLError.h"

#include "protocol/HmacChallengeHandler.h"

using SSLError = liblichtenstein::io::OpenSSLError;
using liblichtenstein::io::TLSClient;

using liblichtenstein::api::HmacChallengeHandler;

/*
 * The client is implemented as a state machine that runs in its own thread. It
 * is responsible for initializing and controlling all other parts of the client
 * which also run as their own threads.
 */
namespace liblichtenstein {
  /**
   * Creates a new lichtenstein client.
   *
   * @param listenIp Address on which the API listens
   * @param apiPort Port the API listens on
   */
  Client::Client(const std::string listenIp, unsigned int apiPort,
                 const std::string certPath, const std::string certKeyPath)
          : apiHost(listenIp), apiPort(apiPort), apiCertPath(certPath),
            apiCertKeyPath(certKeyPath) {
    // create all manner of things
  }

  /**
   * Cleans up all resources associated with the client.
   */
  Client::~Client() {
    // stop all services
    this->stop();
  }


  /**
   * Starts the lichtenstein client. This will create listening sockets and
   * start the client state machine. The service will be advertised via mDNS
   * as well.
   */
  void Client::start() {
    // we need to make sure that all configuration is valid
    this->checkConfig();

    // set up the thread for the client state machine
    this->stateMachineShutdown = false;
    this->stateMachineThread = std::make_unique<std::thread>(
            &Client::stateMachine, this);
  }

  /**
   * This ensures that all required parameters are set correctly before any
   * services can be started.
   */
  void Client::checkConfig() {
    // UUID must not be nil
    if(this->nodeUuid.is_nil()) {
      throw std::invalid_argument("Node UUID may not be nil");
    }

    // we should have a data store
    if(this->dataStore == nullptr) {
      throw std::invalid_argument("No data store configured");
    }
  }


  /**
   * Stops the lichtenstein client. All connections are closed, and the service
   * is not broadcast anymore.
   */
  void Client::stop() {
    // shut down the state machine
    this->setNextState(SHUTDOWN);

    if (this->stateMachineThread) {
      // wait for thread to complete (if it hasn't already)
      if (this->stateMachineThread->joinable()) {
        this->stateMachineThread->join();
      }

      this->stateMachineThread = nullptr;
    }
  }

  /**
   * Starts the realtime protocol handler.
   */
  void Client::startRt() {
    // read the hostname and port from the config
    auto host = this->dataStore->get("rt.host");
    auto portStr = this->dataStore->get("rt.port");

    if(!host.has_value() || !portStr.has_value()) {
      // we were missing either the host or port value
      LOG(ERROR) << "Missing host or port in data store, invalidating adoption";
      this->dataStore->set("adoption.valid", "0");

      throw std::runtime_error("Missing host or port in data store");
    }

    // attempt to connect
    unsigned int port = std::stoi(portStr.value());

    this->rtClient = std::make_unique<api::RealtimeClient>(this, host.value(),
                                                           port);

    // done!
    this->setNextState(IDLE);
  }

  /**
   * Terminates the realtime protocol handler. This closes the DTLS connection
   * and attempts to join the worker thread.
   */
  void Client::stopRt() {
    // deallocating is all we need to do to stop it
    this->rtClient = nullptr;
  }


  /**
   * This implements the "main loop" of the client state machine.
   */
  void Client::stateMachine() {
    // start advertising via mDNS
    VLOG(1) << "Beginning mDNS advertisement";

    this->clientService = mdns::Service::create("_licht._tcp.,_client-api-v1",
                                                this->apiPort);

    if(this->clientService) {
      this->clientService->startAdvertising();
      this->clientService->setTxtRecord("version", "0.1");
      this->clientService->setTxtRecord("type", "client");
      this->clientService->setTxtRecord("uuid", to_string(this->nodeUuid));
    }


    // set up API server thread
    VLOG(1) << "Setting up API server";

    this->apiHandler = new api::API(this->apiHost, this->apiPort,
                                    this->apiCertPath,
                                    this->apiCertKeyPath, this);



    // main state machine
    while (!this->stateMachineShutdown) {
      VLOG(2) << "State machine changed to: " << this->stateMachineCurrent;

      switch (this->stateMachineCurrent) {
        /*
         * This is the "power on" state of the state machine. The serialized
         * state is checked to see the adoption status and go from there.
         */
        case START: {
          // are we adopted (per our data store)
          if(this->isAdopted()) {
            // we have been adopted, so verify it
            this->stateMachineCurrent = VERIFY_ADOPT;
          } else {
            // we are not; go idle and wait for adoption
            LOG(INFO) << "Node is not adopted; waiting for adoption";
            this->stateMachineCurrent = IDLE;
          }
          break;
        }

          /**
           * Establishes the realtime service connection
           */
        case START_RT: {
          // this attempts to initialize the realtime connection
          this->startRt();
          break;
        }

          /*
           * Waits for the condition variable to be signaled; this would be done
           * when an event happened elsewhere in the code.
           */
        case IDLE: {
          std::unique_lock lock(this->stateMachineCvLock);
          this->stateMachineCv.wait(lock, [this] {
            return (this->stateMachineWakeUp == true);
          });

          // clear the "wake up" flag
          this->stateMachineWakeUp = false;
          break;
        }

          /*
           * Causes the state machine to start shutting down.
           */
        case SHUTDOWN: {
          // stop advertising the service via mDNS
          if (this->clientService) {
            VLOG(2) << "Shutting down mDNS advertisement";
            this->clientService->stopAdvertising();
          }

          // ensure the state machine terminates
          this->stateMachineShutdown = true;
          break;
        }

          /**
           * Verify the stored adoption information. This attempts to connect to
           * the server (whose address we have stored), then requests the state of
           * this adoption.
           *
           * If this step is successful, we establish a connection to the realtime
           * data service, and have an already authenticated server API connection
           *
           * On failure, we wait a random amount of time (with exponential
           * increase) and try to verify the adoption again.
           */
        case VERIFY_ADOPT: {
          try {
            // attempt connection; if it doesn't throw we're set :)
            this->verifyAdoption();
          } catch(std::exception &e) {
            // we failed to set up the connection
            LOG(ERROR) << "Failed to verify adoption: " << e.what();

            // TODO: try again after some time instead of going back to idle
            this->setNextState(IDLE);
          }

          break;
        }
      }
    }

    // clean up the server API connection
    if(this->serverApiClient) {
      this->serverApiClient->close();
      this->serverApiClient = nullptr;
    }

    // clean up API server thread
    VLOG(1) << "Shutting down API";
    delete this->apiHandler;
    this->apiHandler = nullptr;

    // clean up realtime connection if it was ever started
    this->stopRt();

    VLOG(2) << "State machine is done, bye bye";
  }

  /**
   * Sets the next state of the state machine and wakes it up from idle.
   *
   * @param next New state
   */
  void Client::setNextState(StateMachineState next) {
    // ensure the state machine is running
    if (this->stateMachineThread == nullptr) return;

    VLOG(1) << "Requested change to state " << next;

    // take the lock while we modify state
    {
      std::unique_lock lock(this->stateMachineCvLock);

      this->stateMachineCurrent = next;
      this->stateMachineWakeUp = true;
    }

    // notify state machine
    this->stateMachineCv.notify_one();
  }

  /**
   * Attempts to use the stored hostname/port combination to connect to the
   * server.
   */
  void Client::attemptServerConnection() {
    // get server info
    auto host = this->dataStore->get("server.host");
    auto port = this->dataStore->get("server.port");

    if(!host.has_value() || !port.has_value()) {
      // we were missing either the host or port value
      LOG(ERROR)
              << "Missing host or port in data store, invalidating adoption state";
      this->dataStore->set("adoption.valid", "0");

      throw std::runtime_error("Missing host or port in data store");
    }

    // try to connect
    int portNum = std::stoi(port.value());

    this->serverApiClient = std::make_unique<TLSClient>(host.value(),
                                                        portNum);

    // TODO: configure the certificate validation

    // validate the adoption state
    auto token = this->dataStore->get("adoption.secret");

    if(!token.has_value()) {
      LOG(ERROR) << "Missing adoption token";
      this->dataStore->set("adoption.valid", "0");

      throw std::runtime_error("Missing adoption token in data store");
    }

    if(!this->validateAdoptionToken(token.value())) {
      // it was not valid, so clear state and return
      LOG(ERROR) << "Server rejected token, invalidating adoption";
      this->dataStore->set("adoption.valid", "0");

      this->serverApiClient->close();
      this->serverApiClient = nullptr;

      throw std::runtime_error("Failed to authenticate with server");
    }

    // success, the connection was authenticated
  }

  /**
   * Validates the provided adoption token with the server. This is done by
   * handling the challenge/response
   *
   * @param token Adoption token
   */
  bool Client::validateAdoptionToken(const std::string &token) {
    // crate the HMAC auth handler
    HmacChallengeHandler handler(this->serverApiClient, token, this->nodeUuid);

    try {
      handler.authenticate();
    } catch(std::exception &e) {
      LOG(ERROR) << "Failed to authenticate: " << e.what();

      throw e;
//      return false;
    }

    // if we get here, authentication was successful
    return true;
  }
}