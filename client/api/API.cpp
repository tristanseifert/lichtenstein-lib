//
// Created by Tristan Seifert on 2019-08-18.
//

#include "API.h"
#include "ClientHandler.h"

#include <glog/logging.h>

#include <system_error>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "../io/OpenSSLError.h"
#include "../io/SSLSessionClosedError.h"
#include "../io/TLSServer.h"
#include "../io/GenericServerClient.h"


namespace liblichtenstein::api {
  /**
   * Initializes the API handler.
   *
   * @param listenHost Host on which to listen
   * @param port Port on which to listen
   * @param certPath Path to the certificate
   * @param certKeyPath Path to the certificate private key
   */
  API::API(std::string &listenHost, const unsigned int port,
           std::string &certPath,
           std::string &certKeyPath) : listenAddress(
          listenHost), listenPort(port), certPath(certPath), certKeyPath(
          certKeyPath) {
    // create the API thread
    this->shutdown = false;
    this->thread = new std::thread(&API::apiEntry, this);
  }

  /**
   * Tears down the API handler.
   */
  API::~API() {
    int err;

    // mark to the API to terminate
    this->shutdown = true;

    // close the listening socket and join that thread
    if(socket != -1) {
      err = close(this->socket);
      PLOG_IF(ERROR, err != 0) << "close() on API socket failed";
    }

    if(this->thread) {
      if(this->thread->joinable()) {
        this->thread->join();
      }

      delete this->thread;
      this->thread = nullptr;
    }
  }


  /**
   * Entry point for the API worker thread
   */
  void API::apiEntry() {
    int err;

    // create socket and listen on it
    this->apiCreateSocket();

    err = listen(this->socket, 5);
    PCHECK(err == 0) << "listen() failed";

    // now, create the TLS server
    this->tlsServer = new io::TLSServer(this->socket);
    this->tlsServer->loadCert(this->certPath, this->certKeyPath);

    // API server main loop
    while(!this->shutdown) {
      try {
        // try to get a client
        auto client = this->tlsServer->run();

        // instantiate a handler and add it to our list
        auto *handler = new ClientHandler(this, client);
        this->clients.emplace_back().reset(handler);
      } catch (io::OpenSSLError &e) {
        LOG(ERROR) << "TLS error accepting client: " << e.what();
      } catch (std::system_error &e) {
        // if it's "connection aborted", ignore it
        if (e.code().value() == ECONNABORTED) {
          VLOG(1) << "Listening socket was closed";
        } else {
          LOG(ERROR) << "System error accepting client: " << e.what();
        }
      } catch (std::runtime_error &e) {
        LOG(ERROR) << "Runtime error accepting client: " << e.what();
      } catch (std::exception &e) {
        LOG(FATAL) << "Unexpected error accepting client" << e.what();
      }
    }

    // close all clients
    this->clients.clear();

    // delete the API server
    delete this->tlsServer;
    this->tlsServer = nullptr;

    // close socket (XXX: state machine does this for us)
    // close(this->socket);
    // this->socket = -1;
  }

  /**
   * Creates the listening socket needed for the API.
   */
  void API::apiCreateSocket() {
    int err;
    struct sockaddr_in servaddr{};

    int on = 1;

    // parse the address
    servaddr.sin_family = AF_INET;
    err = inet_pton(servaddr.sin_family, this->listenAddress.c_str(),
                    &servaddr.sin_addr);

    if (err != 1) {
      // try to parse it as IPv6
      servaddr.sin_family = AF_INET6;
      err = inet_pton(servaddr.sin_family, this->listenAddress.c_str(),
                      &servaddr.sin_addr);

      if (err != 1) {
        // give up and just listen on INADDR_ANY
        memset(&servaddr.sin_addr, 0, sizeof(servaddr.sin_addr));
        servaddr.sin_addr.s_addr = INADDR_ANY;

        LOG(WARNING) << "Couldn't parse listen address '" << this->listenAddress
                     << "', listening on all interfaces instead";
      }
    }

    // create listening socket
    this->socket = ::socket(servaddr.sin_family, SOCK_STREAM, 0);
    PCHECK(this->socket > 0) << "socket() failed";

    servaddr.sin_port = htons(this->listenPort);

    // bind to the given address
    err = bind(this->socket, (const struct sockaddr *) &servaddr,
               sizeof(servaddr));
    PCHECK(err >= 0) << "bind() failed";

    // allow address reuse
    setsockopt(this->socket, SOL_SOCKET, SO_REUSEADDR, (const void *) &on,
               (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
    setsockopt(this->socket, SOL_SOCKET, SO_REUSEPORT, (const void *) &on,
               (socklen_t) sizeof(on));
#endif

    // the socket has been created!
  }
}