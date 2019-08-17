//
// Created by Tristan Seifert on 2019-08-16.
//
#include "../client/io/TLSClient.h"
#include "../client/io/OpenSSLError.h"

#include <iostream>
#include <system_error>
#include <sstream>

#include <glog/logging.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * Performs TLS test.
 *
 * @param hostname Host to connect to
 * @param port Port to connect to
 */
void test_dtls(std::string &hostname, int port) {
  int err;

  // create DTLS instance
  auto *client = new liblichtenstein::io::TLSClient(hostname, port);

  LOG(WARNING) << "disabled peer verification (for testing purposes)";
  client->setVerifyPeer(false);

  // try to write to it
  LOG(INFO) << "trying to write to TLS connection";

  std::string send = "Hello, world!";
  std::vector<char> yen(send.begin(), send.end());
  yen.push_back(0x00);

  err = client->write((std::vector<std::byte> &) yen);
  CHECK(err == yen.size()) << "couldn't write all data: " << err;

  // next, try to read from it
  LOG(INFO) << "trying to read from TLS connection";
  std::vector<std::byte> receive(128);

  err = client->read(receive, receive.capacity());
  LOG(INFO) << "received " << err << " bytes";



  // clean up
  LOG(INFO) << "closing connection";

  client->close();
  delete client;
}

/**
 * Tries to connect to the server (whose address is given as the first argument
 * of the command line) and send some packets.
 *
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char **argv) {
  // initialize logging
  FLAGS_stderrthreshold = 0;
  FLAGS_logtostderr = true;
  FLAGS_v = 2;
  google::InitGoogleLogging(argv[0]);

  // initialize OpenSSL
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  // validate args
  if (argc != 3) {
    std::cerr << "usage: " << argv[0] << " hostname port" << std::endl;
    return -1;
  }

  std::string connectTo = std::string(argv[1]);
  int port = std::stoi(std::string(argv[2]));
  LOG(INFO) << "connecting to " << connectTo << " over TCP";

  // try it
  try {
    test_dtls(connectTo, port);
  } catch (liblichtenstein::io::OpenSSLError &e) {
    LOG(ERROR) << "OpenSSL error: " << e.what();
  } catch (std::system_error &e) {
    LOG(ERROR) << "System error: " << e.what();
  }
}