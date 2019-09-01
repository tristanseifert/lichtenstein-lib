//
// Created by Tristan Seifert on 2019-08-31.
//

#ifndef LIBLICHTENSTEIN_HMACCHALLENGEHANDLER_H
#define LIBLICHTENSTEIN_HMACCHALLENGEHANDLER_H

#include <memory>
#include <string>
#include <cstddef>
#include <vector>
#include <functional>

#include <uuid.h>
#include <google/protobuf/message.h>

#include <openssl/evp.h>

namespace lichtenstein::protocol {
  class Message;

  class AuthChallenge;
}


namespace liblichtenstein::io {
  class GenericTLSClient;
}

namespace liblichtenstein::helpers {
  /**
   * This class handles the HMAC challenge/response authentication when
   * connecting to a server.
   */
  class HmacChallengeHandler {
      using protoMessageType = lichtenstein::protocol::Message;

    public:
      static const std::string MethodName;

    public:
      HmacChallengeHandler() = delete;

      HmacChallengeHandler(std::shared_ptr<io::GenericTLSClient> client,
                           const std::string &secret, const uuids::uuid &uuid);

      void authenticate();

    private:
      void sendAuthHello();

      void getAuthChallenge();

      void respondToChallenge(lichtenstein::protocol::AuthChallenge &challenge);

      void sendAuthResponse(std::vector<std::byte> &hmac,
                            std::vector<std::byte> &nonce);

      void getAuthState();

    private:
      void doHmac(std::vector<std::byte> &outBuffer, const EVP_MD *fn,
                  const std::vector<std::byte> &nonce);

    private:
      void sendMessage(google::protobuf::Message &response);

      void decodeMessage(protoMessageType &outMessage,
                         std::vector<std::byte> &buffer);

      void readMessage(const std::function<void(protoMessageType &)> &success);

    private:
      // UUID to send in the AuthHello
      uuids::uuid uuid;

      // connection to the server on which we communicate
      std::shared_ptr<io::GenericTLSClient> client;
      // secret for HMAC
      std::string hmacSecret;
  };
}


#endif //LIBLICHTENSTEIN_HMACCHALLENGEHANDLER_H
