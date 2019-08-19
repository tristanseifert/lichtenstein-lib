//
// Created by Tristan Seifert on 2019-08-17.
//
#include "Client.h"

#include <glog/logging.h>

#include <utility>

#include "io/mdns/Service.h"

#include "api/API.h"

#include "io/OpenSSLError.h"
#include "io/DTLSClient.h"




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
    this->stateMachineThread = new std::thread(&Client::stateMachine, this);
  }

  /**
   * This ensures that all required parameters are set correctly before any
   * services can be started.
   */
  void Client::checkConfig() {

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

      // deallocate all of its resources
      delete this->stateMachineThread;
      this->stateMachineThread = nullptr;
    }
  }

  /**
   * Terminates the realtime protocol handler. This closes the DTLS connection
   * and attempts to join the worker thread.
   */
  void Client::stopRt() {
    // mark to the handler to terminate and close the client connection
    this->rtShutdown = true;
    this->rtClient->close();

    // join the protocol handler thread
    this->rtThread->join();
    delete this->rtThread;
  }


  /**
   * This implements the "main loop" of the client state machine.
   */
  void Client::stateMachine() {
    // start advertising via mDNS
    VLOG(1) << "Beginning mDNS advertisement";

    this->clientService = mdns::Service::create("_licht._tcp.", this->apiPort);

    if(this->clientService) {
      this->clientService->startAdvertising();
      this->clientService->setTxtRecord("vers", "0.1");
      this->clientService->setTxtRecord("typ", "client");
    }


    // set up API server thread
    VLOG(1) << "Setting up API server";

    this->apiHandler = new api::API(this->apiHost, this->apiPort,
                                    this->apiCertPath,
                                    this->apiCertKeyPath);



    // main state machine
    while (!this->stateMachineShutdown) {
      VLOG(2) << "State machine changed to: " << this->stateMachineCurrent;

      switch (this->stateMachineCurrent) {
        /*
         * This is the "power on" state of the state machine. The serialized
         * state is checked to see the adoption status and go from there.
         */
        case START: {
          // for now, just idle
          this->stateMachineCurrent = IDLE;
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
      }
    }

    // clean up API server thread
    VLOG(1) << "Shutting down API";
    delete this->apiHandler;
    this->apiHandler = nullptr;

    // clean up realtime connection if it was ever started
    if (this->rtThread) {
      VLOG(1) << "Shutting down realtime channel";
      this->stopRt();
    }

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
}