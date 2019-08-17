//
// Created by Tristan Seifert on 2019-08-16.
//
#include "../client/io/DTLSServer.h"
#include "../client/io/OpenSSLError.h"
#include "../client/io/GenericServerClient.h"

#include <glog/logging.h>

#include <iostream>
#include <system_error>
#include <sstream>
#include <memory>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

static void
test_client(std::shared_ptr<liblichtenstein::io::GenericServerClient> &client) {
  int err, read = 0;

  // write some data
  LOG(INFO) << "Trying to write to DTLS client " << client;

  std::string send = "Hello, world!";
  std::vector<char> yen(send.begin(), send.end());
  yen.push_back(0x00);

  err = client->write((std::vector<std::byte> &) yen);
  CHECK(err == yen.size()) << "couldn't write all data: " << err;
  LOG(INFO) << "Wrote " << err << " of " << yen.size() << " bytes";

  // try to read some data
  std::vector<std::byte> receive(128);

  while (read == 0) {
    err = client->read(receive, (receive.capacity() - read));

    if (err > 0) {
      read += err;
    }
  }

  LOG(INFO) << "Read " << read << " bytes";

  // close that hoe
  LOG(INFO) << "closing connection";
  client->close();
}


/**
 * Opens a listening DTLS server with the specified certificate and key file.
 *
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char **argv) {
  int err, fd;

  int on = 1;

  struct sockaddr_in servaddr{};
  memset(&servaddr, 0, sizeof(servaddr));

  // initialize logging
  FLAGS_stderrthreshold = 0;
  FLAGS_logtostderr = true;
  FLAGS_v = 2;
  google::InitGoogleLogging(argv[0]);

  // initialize OpenSSL
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  // validate args
  if(argc != 4) {
    std::cerr << "usage: " << argv[0] << " cert key port" << std::endl;
    return -1;
  }

  std::string certPath = std::string(argv[1]);
  std::string keyPath = std::string(argv[2]);
  int port = std::stoi(std::string(argv[3]));

  LOG(INFO) << "listening on port " << port;

  // create listening socket
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  PCHECK(fd > 0) << "socket() failed";

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(port);

  err = bind(fd, (const struct sockaddr *) &servaddr, sizeof(servaddr));
  PCHECK(err >= 0) << "bind() failed";

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif

  // try it
  try {
    // create the server and load certificate
    auto *server = new liblichtenstein::io::DTLSServer(fd);
    server->loadCert(certPath, keyPath);

    LOG(INFO) << "created server. awaiting connections";

    // try to handle clients
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while(true) {
      auto client = server->run();

      LOG(INFO) << "got new client: " << client;
      test_client(client);
    }
#pragma clang diagnostic pop
  } catch (liblichtenstein::io::OpenSSLError &e) {
    LOG(ERROR) << "OpenSSL error: " << e.what();
  } catch(std::system_error &e) {
    LOG(ERROR) << "System error: " << e.what();
  }

  // close socket
  close(fd);
}