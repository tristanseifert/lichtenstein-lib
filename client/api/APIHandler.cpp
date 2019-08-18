//
// Created by Tristan Seifert on 2019-08-18.
//

#include "APIHandler.h"

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
  APIHandler::APIHandler(std::string &listenHost, const unsigned int port,
                         std::string &certPath,
                         std::string &certKeyPath) : apiListenHost(
          listenHost), apiPort(port), apiCertPath(certPath), apiCertKeyPath(
          certKeyPath) {
    // create the API thread
    this->apiShutdown = false;
    this->apiThread = new std::thread(&APIHandler::apiEntry, this);
  }

  /**
   * Tears down the API handler.
   */
  APIHandler::~APIHandler() {
    int err;

    // mark to the API to terminate
    this->apiShutdown = true;

    // close the listening socket and join that thread
    if (apiSocket != -1) {
      err = close(this->apiSocket);
      PLOG_IF(ERROR, err != 0) << "close() on API socket failed";
    }

    if (this->apiThread) {
      if (this->apiThread->joinable()) {
        this->apiThread->join();
      }

      delete this->apiThread;
      this->apiThread = nullptr;
    }
  }


  /**
   * Entry point for the API worker thread
   */
  void APIHandler::apiEntry() {
    int err;

    // create socket and listen on it
    this->apiCreateSocket();

    err = listen(this->apiSocket, 5);
    PCHECK(err == 0) << "listen() failed";

    // now, create the TLS server
    this->apiServer = new io::TLSServer(this->apiSocket);
    this->apiServer->loadCert(this->apiCertPath, this->apiCertKeyPath);

    // API server main loop
    while (!this->apiShutdown) {
      // wait for an accepted client
      try {
        auto client = this->apiServer->run();

        // create a new thread to handle this connection
        std::thread *worker = new std::thread(&APIHandler::apiHandleClient,
                                              this, client);

        this->apiClients.push_back({worker, client});
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
    for (auto const&[thread, client] : this->apiClients) {
      VLOG(1) << "Shutting down client " << client << " with thread " << thread;

      // try to close the client
      client->close();

      // wait for thread to join and delete it
      if (thread->joinable()) {
        thread->join();
      }

      delete thread;
    }

    this->apiClients.clear();

    // delete the API server
    delete this->apiServer;
    this->apiServer = nullptr;

    // close socket (XXX: state machine does this for us)
    // close(this->apiSocket);
    // this->apiSocket = -1;
  }

  /**
   * Creates the listening socket needed for the API.
   */
  void APIHandler::apiCreateSocket() {
    int err;
    struct sockaddr_in servaddr{};

    int on = 1;

    // parse the address
    servaddr.sin_family = AF_INET;
    err = inet_pton(servaddr.sin_family, this->apiListenHost.c_str(),
                    &servaddr.sin_addr);

    if (err != 1) {
      // try to parse it as IPv6
      servaddr.sin_family = AF_INET6;
      err = inet_pton(servaddr.sin_family, this->apiListenHost.c_str(),
                      &servaddr.sin_addr);

      if (err != 1) {
        // give up and just listen on INADDR_ANY
        memset(&servaddr.sin_addr, 0, sizeof(servaddr.sin_addr));
        servaddr.sin_addr.s_addr = INADDR_ANY;

        LOG(WARNING) << "Couldn't parse listen address '" << this->apiListenHost
                     << "', listening on all interfaces instead";
      }
    }

    // create listening socket
    this->apiSocket = socket(servaddr.sin_family, SOCK_STREAM, 0);
    PCHECK(this->apiSocket > 0) << "socket() failed";

    servaddr.sin_port = htons(this->apiPort);

    err = bind(this->apiSocket, (const struct sockaddr *) &servaddr,
               sizeof(servaddr));
    PCHECK(err >= 0) << "bind() failed";

    setsockopt(this->apiSocket, SOL_SOCKET, SO_REUSEADDR, (const void *) &on,
               (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
    setsockopt(this->apiSocket, SOL_SOCKET, SO_REUSEPORT, (const void *) &on,
               (socklen_t) sizeof(on));
#endif

    // the socket has been created!
  }


  /**
   * Entry point for a client handler thread. These threads will continually
   * serve requests until either the remote end closes the connection, or the
   * API is being terminated.
   *
   * @param client Connected client
   */
  void
  APIHandler::apiHandleClient(std::shared_ptr<io::GenericServerClient> client) {
    VLOG(1) << "Got new client: " << client;

    // service requests as long as the API is running
    while (!this->apiShutdown) {
      std::vector<std::byte> response;
      int read;

      // try to read from the client
      try {
        read = client->read(response, 8192);

        // decode message
        VLOG(1) << "Got " << read << " bytes from client " << client;
      }
        // an error in the TLS library happened
      catch (io::OpenSSLError &e) {
        // ignore TLS errors if we're shutting down
        if (!this->apiShutdown) {
          LOG(ERROR) << "TLS error reading from client: " << e.what();
        }
      }
        // if we get this exception, session was closed
      catch (io::SSLSessionClosedError &e) {
        VLOG(1) << "Connection was closed by " << client;
        break;
      }
        // some other runtime error happened
      catch (std::runtime_error &e) {
        LOG(ERROR) << "Runtime error reading from client: " << e.what();
      }
    }

    // clean up client
    VLOG(1) << "Shutting down API client for client " << client;
    client->close();
  }
}