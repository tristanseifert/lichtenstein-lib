//
// Created by Tristan Seifert on 2019-08-17.
//
#include "../client/Client.h"

#include <glog/logging.h>

#include <iostream>
#include <system_error>
#include <sstream>
#include <memory>

#include <openssl/ssl.h>

void ignoreCtrlC(int sig) {
  // nothing
}


/**
 * Sets up a basic dummy client to test the client implementation.
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
  if (argc != 5) {
    std::cerr << "usage: " << argv[0] << " listenIp port cert key" << std::endl;
    return -1;
  }

  std::string listenIp = std::string(argv[1]);
  int apiPort = std::stoi(std::string(argv[2]));
  LOG(INFO) << "API will run on  " << listenIp << ':' << apiPort << " over TCP";

  std::string certPath = std::string(argv[3]);
  std::string keyPath = std::string(argv[4]);


  // try it
  try {
    auto *client = new liblichtenstein::Client(listenIp, apiPort, certPath,
                                               keyPath);

    client->start();

    // wait for signal (such as Ctrl+C)
    LOG(INFO) << "Client started, hit Ctrl+C to exit";
    signal(SIGINT, ignoreCtrlC);
    pause();

    // clean up
    LOG(INFO) << "Shutting down client";
    client->stop();
    delete client;
  } catch (std::system_error &e) {
    LOG(ERROR) << "System error: " << e.what();
  } catch (std::exception &e) {
    LOG(ERROR) << "Generic exception: " << e.what();
  }
}