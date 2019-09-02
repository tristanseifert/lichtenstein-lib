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

  class AuthHello;

  class HmacAuthResponse;
}


namespace liblichtenstein::io {
  class GenericTLSClient;

  class GenericServerClient;
}

namespace liblichtenstein::api {
  /**
   * This class handles the HMAC challenge/response authentication when
   * connecting to a server.
   */
  class HmacChallengeHandler {
      using protoMessageType = lichtenstein::protocol::Message;

    public:
      static const std::string MethodName;
      static const size_t kNonceLength = 64;

    public:
      HmacChallengeHandler() = delete;

      HmacChallengeHandler(std::shared_ptr<io::GenericTLSClient> client,
                           const std::string &secret, const uuids::uuid &uuid);

      HmacChallengeHandler(std::shared_ptr<io::GenericServerClient> client,
                           const std::string &secret, const uuids::uuid &uuid);

    public:
      void authenticate();

      void handleAuthentication(const lichtenstein::protocol::AuthHello &hello);

    private:
      void verifyHello(const lichtenstein::protocol::AuthHello &);

      void sendChallenge(const std::vector<std::byte> &);

      void getAuthResponse(const std::vector<std::byte> &,
                           const std::vector<std::byte> &);

      void checkResponse(const std::vector<std::byte> &,
                         const std::vector<std::byte> &,
                         const lichtenstein::protocol::HmacAuthResponse &);

      void sendAuthSuccess();

    private:
      void sendAuthHello();

      void getAuthChallenge();

      void respondToChallenge(lichtenstein::protocol::AuthChallenge &challenge);

      void sendAuthResponse(std::vector<std::byte> &hmac,
                            std::vector<std::byte> &nonce);

      void getAuthState();

    private:
      void handleError(const protoMessageType &message);

    private:
      void doHmac(std::vector<std::byte> &outBuffer, const EVP_MD *fn,
                  const std::vector<std::byte> &nonce);

      void generateRandom(std::vector<std::byte> &outBuffer, size_t bytes);

    private:
      void sendMessage(google::protobuf::Message &response);

      void decodeMessage(protoMessageType &outMessage,
                         std::vector<std::byte> &buffer);

      void readMessage(const std::function<void(protoMessageType &)> &success);

    private:
      // UUID to send in the AuthHello
      uuids::uuid uuid;
      // secret for HMAC
      std::string hmacSecret;

    private:
      // connection to the server on which we communicate
      std::shared_ptr<io::GenericTLSClient> client;
      // server client (for verification)
      std::shared_ptr<io::GenericServerClient> serverClient;

    private:
      // read function
      std::function<size_t(std::vector<std::byte> &, size_t)> readCallback;
      // write function
      std::function<size_t(const std::vector<std::byte> &)> writeCallback;

  };
}


#endif //LIBLICHTENSTEIN_HMACCHALLENGEHANDLER_H
