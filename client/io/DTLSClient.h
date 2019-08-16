//
// Created by Tristan Seifert on 2019-08-16.
//

#ifndef LIBLICHTENSTEIN_DTLSCLIENT_H
#define LIBLICHTENSTEIN_DTLSCLIENT_H

#include "GenericTLSClient.h"

#include <cstddef>
#include <vector>
#include <string>

#include <netdb.h>

namespace liblichtenstein {
  class DTLSClient : public GenericTLSClient {
    public:
      DTLSClient(std::string host, int port);
      virtual ~DTLSClient();

    public:
      virtual size_t write(const std::vector<std::byte> &data);

      virtual size_t read(std::vector<std::byte> &data, size_t wanted);

    private:
      void createContext();

      void resolveHost();
      void createSocket();
      void connectSocket();

    private:
      struct addrinfo *servinfo = nullptr;
      struct addrinfo connectedAddr;
  };
}

#endif //LIBLICHTENSTEIN_DTLSCLIENT_H
