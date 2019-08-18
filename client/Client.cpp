//
// Created by Tristan Seifert on 2019-08-17.
//
#include "Client.h"

#include <glog/logging.h>

#include <utility>

#include "mdns/Service.h"

#if __APPLE__

#include "mdns/AppleService.h"

#else
#warning "mDNS is not supported on this platform"
#endif

#include "io/TLSServer.h"
#include "io/DTLSClient.h"


namespace liblichtenstein {
  /**
   * Creates a new lichtenstein client.
   *
   * @param listenIp Address on which the API listens
   * @param apiPort Port the API listens on
   */
  Client::Client(std::string listenIp, unsigned int apiPort) : apiListenHost(
          std::move(listenIp)), apiPort(apiPort) {
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

    // start advertising the API
#if __APPLE__
    this->clientService = new mdns::AppleService("_licht._tcp.", this->apiPort);
#endif

    if (this->clientService) {
      this->clientService->startAdvertising();
      this->clientService->setTxtRecord("vers", "1.0");
      this->clientService->setTxtRecord("typ", "client");
    }
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
    // stop broadcasting
    if (this->clientService) {
      this->clientService->stopAdvertising();
    }

    // shut down the realtime protocol and API handlers
    this->stopRt();
    this->stopApi();
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
   * Terminates the client API server. The TLS server is stopped, any worker
   * threads used to process requests are killed, until the server thread itself
   * is stopped.
   */
  void Client::stopApi() {
    int err;

    // mark to the API to terminate
    this->apiShutdown = true;

    // close the listening socket and join that thread
    err = close(this->apiSocket);
    PLOG_IF(ERROR, err != 0) << "close() on API socket failed";

    this->apiThread->join();
    delete this->apiThread;
  }
}