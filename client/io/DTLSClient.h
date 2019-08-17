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
  namespace io {
    class DTLSClient : public GenericTLSClient {
      public:
        DTLSClient(std::string host, int port);

        ~DTLSClient() override;

      private:
        void createContext();

        void createSocket();

        void connectSocket();

      private:
        struct addrinfo *servinfo = nullptr;
        struct addrinfo connectedAddr{};
    };
  }
}

#endif //LIBLICHTENSTEIN_DTLSCLIENT_H
