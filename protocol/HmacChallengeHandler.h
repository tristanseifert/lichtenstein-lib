//
// Created by Tristan Seifert on 2019-08-31.
//

#ifndef LIBLICHTENSTEIN_HMACCHALLENGEHANDLER_H
#define LIBLICHTENSTEIN_HMACCHALLENGEHANDLER_H

#include "MessageIO.h"

#include <memory>
#include <string>
#include <cstddef>
#include <vector>

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
  class MessageIO;

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

      HmacChallengeHandler(std::shared_ptr<MessageIO> io,
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
      // UUID to send in the AuthHello
      uuids::uuid uuid;
      // secret for HMAC
      std::string hmacSecret;

    private:
      // we do all our message IO on this object
      std::shared_ptr<MessageIO> io;
  };
}


#endif //LIBLICHTENSTEIN_HMACCHALLENGEHANDLER_H
