//
// Created by Tristan Seifert on 2019-08-31.
//

#ifndef LIBLICHTENSTEIN_REALTIMECLIENT_H
#define LIBLICHTENSTEIN_REALTIMECLIENT_H

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <cstddef>
#include <vector>
#include <functional>

#include <google/protobuf/message.h>

namespace lichtenstein::protocol {
  class Message;
}

namespace liblichtenstein {
  class Client;
}

namespace liblichtenstein::io {
  class DTLSClient;
}

namespace liblichtenstein::api {
  /**
   * This provides the interface to the server's realtime data API, which is
   * primarily used to receive pixel data.
   *
   * It's automagically instantiated once the adoption token has been validated.
   */
  class RealtimeClient {
      using protoMessageType = lichtenstein::protocol::Message;

    public:
      RealtimeClient() = delete;

      RealtimeClient(Client *client, const std::string &host,
                     const unsigned int port);

      ~RealtimeClient();

    private:
      void threadEntry();

    private:
      void sendMessage(google::protobuf::Message &response);

      void decodeMessage(protoMessageType &outMessage,
                         std::vector<std::byte> &buffer);

      void readMessage(const std::function<void(protoMessageType &)> &success);

    private:
      // client instance
      Client *client = nullptr;

      // worker thread for handling the realtime protocol
      std::unique_ptr<std::thread> thread = nullptr;
      // whether the real time client is shutting down
      std::atomic_bool shutdown = false;
      // DTLS client to realtime API
      std::shared_ptr<io::DTLSClient> dtlsClient;
  };
}


#endif //LIBLICHTENSTEIN_REALTIMECLIENT_H
