//
// Created by Tristan Seifert on 2019-08-16.
//
#include "../client/io/DTLSClient.h"
#include "../client/io/OpenSSLError.h"

#include <iostream>
#include <system_error>
#include <sstream>

#include <glog/logging.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * Performs DTLS test.
 *
 * @param hostname Host to connect to
 * @param port Port to connect to
 */
void test_dtls(std::string hostname, int port) {
  int err;

  // create DTLS instance
  auto *client = new liblichtenstein::DTLSClient(hostname, port);

  // try to write to it
  std::cout << "trying to write to DTLS connection" << std::endl;

  std::string send = "Hello, world!";
  std::vector<char> yen(send.begin(), send.end());
  yen.push_back(0x00);

  err = client->write((std::vector<std::byte> &) yen);
  CHECK(err == yen.size()) << "couldn't write all data: " << err;

  // next, try to read from it
  std::vector<std::byte> receive(128);

  err = client->read(receive, receive.capacity());
  std::cout << "received " << err << " bytes" << std::endl;



  // clean up
  std::cout << "closing connection" << std::endl;

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
  int err;

  // initialize OpenSSL
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  // validate args
  if(argc != 3) {
    std::cerr << "usage: " << argv[0] << " hostname port" << std::endl;
    return -1;
  }

  std::string connectTo = std::string(argv[1]);
  int port = std::stoi(std::string(argv[2]));
  std::cout << "connecting to " << connectTo << std::endl;

  // try it
  try {
    test_dtls(connectTo, port);
  } catch(liblichtenstein::OpenSSLError &e) {
    std::cerr << "OpenSSL error: " << e.what() << std::endl;
  } catch(std::system_error &e) {
    std::cerr << "System error: " << e.what() << std::endl;
  }

}