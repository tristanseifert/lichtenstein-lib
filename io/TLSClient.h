//
// Created by Tristan Seifert on 2019-08-16.
//

#ifndef LIBLICHTENSTEIN_TLSCLIENT_H
#define LIBLICHTENSTEIN_TLSCLIENT_H

#include "GenericTLSClient.h"

#include <cstddef>
#include <vector>
#include <string>

#include <netdb.h>


namespace liblichtenstein {
  namespace io {
    class TLSClient : public GenericTLSClient {
      public:
        TLSClient(std::string host, int port);

        ~TLSClient() override;

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


#endif //LIBLICHTENSTEIN_TLSCLIENT_H
