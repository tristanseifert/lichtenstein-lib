//
// Created by Tristan Seifert on 2019-08-31.
//
#include "HmacChallengeHandler.h"

#include "version.h"
#include "MessageSerializer.h"
#include "WireMessage.h"
#include "ProtocolError.h"

#include "proto/shared/Message.pb.h"

#include "proto/shared/Error.pb.h"
#include "proto/shared/AuthHello.pb.h"
#include "proto/shared/AuthChallenge.pb.h"
#include "proto/shared/AuthResponse.pb.h"
#include "proto/shared/AuthState.pb.h"
#include "proto/shared/HmacAuthChallenge.pb.h"
#include "proto/shared/HmacAuthResponse.pb.h"

#include "../io/GenericTLSClient.h"
#include "../io/GenericServerClient.h"
#include "../io/OpenSSLError.h"

#include <glog/logging.h>

#include <google/protobuf/message.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>


using liblichtenstein::api::MessageSerializer;
using liblichtenstein::api::ProtocolError;
using liblichtenstein::io::OpenSSLError;

using lichtenstein::protocol::Error;
using lichtenstein::protocol::AuthHello;
using lichtenstein::protocol::AuthState;
using lichtenstein::protocol::AuthChallenge;
using lichtenstein::protocol::HmacAuthChallenge;
using lichtenstein::protocol::AuthResponse;
using lichtenstein::protocol::HmacAuthResponse;


namespace liblichtenstein::api {
  const std::string HmacChallengeHandler::MethodName = "me.tseifert.lichtenstein.auth.hmac";

  /**
   * Creates a new instance of the HMAC challenge handler that's works on a
   * connected client.
   *
   * @param client A connected TLS client to authenticate
   * @param secret HMAC secret
   * @param uuid UUID to send/expect
   */
  HmacChallengeHandler::HmacChallengeHandler(
          std::shared_ptr<io::GenericTLSClient> client,
          const std::string &secret, const uuids::uuid &uuid) : client(client),
                                                                hmacSecret(
                                                                        secret),
                                                                uuid(uuid) {
    // assign the callbacks for client
    this->readCallback = [this](std::vector<std::byte> &data, size_t wanted) {
      return this->client->read(data, wanted);
    };

    this->writeCallback = [this](const std::vector<std::byte> &data) {
      return this->client->write(data);
    };
  }

  HmacChallengeHandler::HmacChallengeHandler(
          std::shared_ptr<io::GenericServerClient> client,
          const std::string &secret, const uuids::uuid &uuid) : serverClient(
          client), hmacSecret(secret), uuid(uuid) {
    // assign callbacks for a server connection
    this->readCallback = [this](std::vector<std::byte> &data, size_t wanted) {
      return this->serverClient->read(data, wanted);
    };

    this->writeCallback = [this](const std::vector<std::byte> &data) {
      return this->serverClient->write(data);
    };
  }


  /**
   * Handles an authentication request in server mode, e.g. issuing the
   * challenge and ensuring that the value we get back is the expected one.
   *
   * @param message Received AuthHello message
   */
  void HmacChallengeHandler::handleAuthentication(const AuthHello &hello) {
    // validate the hello
    this->verifyHello(hello);

    // generate random data for the challenge and send it
    std::vector<std::byte> nonce;
    this->generateRandom(nonce, kNonceLength);

    CHECK(nonce.size() > 0)
                    << "Nonce cannot be empty, this should never happen";

    this->sendChallenge(nonce);

    // compute the HMAC (so we can verify it) (TODO: make hash fn configurable)
    std::vector<std::byte> computedHmac;
    this->doHmac(computedHmac, EVP_whirlpool(), nonce);

    // read the challenge response, this also verifies the response
    this->getAuthResponse(computedHmac, nonce);

    // if we get here, auth was successful, so send the success message
    this->sendAuthSuccess();
  }

  /**
   * Verifies a received AuthHello to have the proper UUID field, and supports
   * any of our methods. If a condition fails, an exception is generated.
   *
   * @param hello Received AuthHello message
   */
  void HmacChallengeHandler::verifyHello(const AuthHello &hello) {
    // verify that the UUID matches
    auto uuidData = hello.uuid().data();
    std::array<uuids::uuid::value_type, 16> uuidArray{};
    std::copy(uuidData, uuidData + 16, uuidArray.begin());

    uuids::uuid receivedUuid(uuidArray);

    if(receivedUuid != this->uuid) {
      std::stringstream error;

      error << "Received UUID: " << to_string(receivedUuid) << ", expected ";
      error << to_string(this->uuid);

      throw std::runtime_error(error.str().c_str());
    }

    // make sure that the supported methods contains the HMAC method
    bool supported = false;

    for(int i = 0; i < hello.supportedmethods_size(); i++) {
      auto method = hello.supportedmethods(i);

      if(method == MethodName) {
        supported = true;
        break;
      }
    }

    if(!supported) {
      std::stringstream error;

      error << "Could not find a supported authentication method (expected ";
      error << MethodName << ")";

      throw std::runtime_error(error.str().c_str());
    }
  }

  /**
   * Sends a challenge to the client. Currently, we will use Whirlpool as the
   * HMAC method regardless of any other configuration.
   *
   * @param nonce Generated nonce data
   */
  void
  HmacChallengeHandler::sendChallenge(const std::vector<std::byte> &nonce) {
    // fill out the wrapper challenge
    AuthChallenge challenge;

    challenge.set_method(MethodName);

    // fill in the Hmac challenge message
    HmacAuthChallenge hmacChallenge;

    hmacChallenge.set_function(
            lichtenstein::protocol::HmacAuthChallenge_HashFunction_WHIRLPOOL);
    hmacChallenge.set_nonce(nonce.data(), nonce.size());

    // insert it into the auth challenge wrapper
    challenge.mutable_payload()->PackFrom(hmacChallenge);

    // send it
    this->sendMessage(challenge);
  }

  /**
   * Attempts to receive an AuthResponse message.
   *
   * @param computed Precomputed correct HMAC
   */
  void
  HmacChallengeHandler::getAuthResponse(const std::vector<std::byte> &computed,
                                        const std::vector<std::byte> &nonce) {
    this->readMessage([this, computed, nonce](protoMessageType &message) {
      std::string type = message.payload().type_url();

      // is it an error?
      if(type == "type.googleapis.com/lichtenstein.protocol.Error") {
        this->handleError(message);
      }
      // is it an auth response?
      if(type == "type.googleapis.com/lichtenstein.protocol.AuthResponse") {
        // unpack the outer message
        AuthResponse response;
        if(!message.payload().UnpackTo(&response)) {
          throw std::runtime_error("Failed to unpack AuthResponse");
        }

        // then, unpack the HMAC message
        HmacAuthResponse hmacResponse;
        if(!response.payload().UnpackTo(&hmacResponse)) {
          throw std::runtime_error("Failed to unpack HmacAuthResponse");
        }

        // we got the response, so check it
        this->checkResponse(computed, nonce, hmacResponse);
      }
        // we received a message type we didn't expect
      else {
        std::stringstream error;
        error << "Received unexpected message type '" << type << "'; expected ";
        error << "Error or AuthResponse";
        throw ProtocolError(error.str().c_str());
      }
    });
  }

  /**
   * Validates a received HMAC challenge; this makes sure that the nonce that
   * was sent back is identical to what we sent, and that the HMAC matches what
   * we precomputed.
   *
   * @param computed Computed HMAC
   * @param nonce Random nonce we sent
   * @param response Received HMAC challenge
   */
  void
  HmacChallengeHandler::checkResponse(const std::vector<std::byte> &computed,
                                      const std::vector<std::byte> &nonce,
                                      const HmacAuthResponse &response) {
    // do the nonce bytes match?
    auto receivedNoncePtr = reinterpret_cast<const std::byte *>(response.nonce().data());
    auto receivedNonceLen = response.nonce().length();

    std::vector<std::byte> receivedNonce;
    receivedNonce.reserve(receivedNonceLen);
    std::copy(receivedNoncePtr, receivedNoncePtr + receivedNonceLen,
              receivedNonce.begin());

    if(receivedNonce != nonce) {
      throw std::runtime_error(
              "Received nonce is not the same as what was sent");
    }

    // do the HMAC bytes match?
    auto receivedHmacPtr = reinterpret_cast<const std::byte *>(response.hmac().data());
    auto receivedHmacLen = response.hmac().length();

    std::vector<std::byte> receivedHmac;
    receivedHmac.reserve(receivedHmacLen);
    std::copy(receivedHmacPtr, receivedHmacPtr + receivedHmacLen,
              receivedHmac.begin());

    if(receivedHmac != computed) {
      throw std::runtime_error("Received HMAC is incorrect");
    }

    // if we get here, the response was correct
  }

  /**
   * Sends the auth success message to the client
   */
  void HmacChallengeHandler::sendAuthSuccess() {
    AuthState state;

    state.set_success(true);

    this->sendMessage(state);
  }


  /**
   * Attempts to authenticate in client mode, e.g. responding to the challenge.
   */
  void HmacChallengeHandler::authenticate() {
    // first, send the AuthHello
    this->sendAuthHello();

    // wait for the challenge; this will also send an AuthResponse
    this->getAuthChallenge();

    // lastly, wait for the status response
    this->getAuthState();
  }
  /**
   * Sends the "AuthHello" message.
   */
  void HmacChallengeHandler::sendAuthHello() {
    AuthHello hello;

    // get uuid
    auto uuidData = this->uuid.as_bytes();
    hello.set_uuid(uuidData.data(), uuidData.size());

    // we support only the HMAC method
    hello.add_supportedmethods(HmacChallengeHandler::MethodName);

    // send the message
    this->sendMessage(hello);
  }
  /**
   * Waits to receive an AuthChallenge or an AuthState (error) message.
   */
  void HmacChallengeHandler::getAuthChallenge() {
    this->readMessage([this](protoMessageType &message) {
      std::string type = message.payload().type_url();

      // is it an error message?
      if(type == "type.googleapis.com/lichtenstein.protocol.Error") {
        this->handleError(message);
      }

        // is it an auth challenge?
      else if(type ==
              "type.googleapis.com/lichtenstein.protocol.AuthChallenge") {
        AuthChallenge challenge;
        if(!message.payload().UnpackTo(&challenge)) {
          throw ProtocolError("Failed to unpack AuthChallenge");
        }

        this->respondToChallenge(challenge);
      }

        // undefined message type :(
      else {
        std::stringstream error;

        error << "Received unexpected message type '" << type << "'; expected ";
        error << "Error or AuthChallenge";

        throw ProtocolError(error.str().c_str());
      }
    });
  }
  /**
   * Responds to a received authentication challenge.
   *
   * @param challenge Received challenge
   */
  void HmacChallengeHandler::respondToChallenge(AuthChallenge &challenge) {
    // ensure the method is correct
    if(challenge.method() != MethodName) {
      std::stringstream error;

      error << "Server chose unsupported auth method '" << challenge.method();
      error << "'";

      throw ProtocolError(error.str().c_str());
    }

    // attempt to decode the message
    HmacAuthChallenge hmacChallenge;

    if(!challenge.payload().UnpackTo(&hmacChallenge)) {
      throw ProtocolError("Failed to unpack HMAC challenge");
    }

    // copy nonce into a vector
    auto nonceStr = hmacChallenge.nonce();
    std::vector<std::byte> nonce;
    nonce.reserve(nonceStr.length());

    for(auto &c : nonceStr) {
      nonce.push_back(static_cast<std::byte>(c));
    }

    // calculate the response
    std::vector<std::byte> hmacData;

    switch(hmacChallenge.function()) {
      case HmacAuthChallenge::HashFunction::HmacAuthChallenge_HashFunction_SHA1:
        this->doHmac(hmacData, EVP_sha1(), nonce);
        break;

      case HmacAuthChallenge::HashFunction::HmacAuthChallenge_HashFunction_WHIRLPOOL:
        this->doHmac(hmacData, EVP_whirlpool(), nonce);
        break;

      default: {
        std::stringstream error;
        error << "Unknown HMAC function: " << hmacChallenge.function();
        throw ProtocolError(error.str().c_str());
        break;
      }
    }

    // make sure the HMAC generated data
    if(hmacData.empty()) {
      throw std::runtime_error("HMAC failed to produce data");
    }

    // produce a response message
    this->sendAuthResponse(hmacData, nonce);
  }
  /**
   * Constructs an AuthResponse message to the server with the given HMAC and
   * nonce data.
   *
   * @param hmac Calculated HMAC
   * @param nonce Data provided in AuthChallenge
   */
  void HmacChallengeHandler::sendAuthResponse(std::vector<std::byte> &hmac,
                                              std::vector<std::byte> &nonce) {
    // construct the HMAC message
    HmacAuthResponse hmacResponse;

    hmacResponse.set_hmac(hmac.data(), hmac.size());
    hmacResponse.set_nonce(nonce.data(), nonce.size());

    // insert it into an AuthResponse
    AuthResponse response;

    auto *any = new google::protobuf::Any();
    any->PackFrom(hmacResponse);

    response.set_allocated_payload(any);

    // send it
    this->sendMessage(response);
  }
  /**
   * Waits to receive an AuthState message.
   */
  void HmacChallengeHandler::getAuthState() {
    this->readMessage([this](protoMessageType &message) {
      std::string type = message.payload().type_url();

      // is it an error message?
      if(type == "type.googleapis.com/lichtenstein.protocol.Error") {
        this->handleError(message);
      }
        // is it an auth state
      else if(type == "type.googleapis.com/lichtenstein.protocol.AuthState") {
        AuthState state;
        if(!message.payload().UnpackTo(&state)) {
          throw ProtocolError("Failed to unpack AuthState");
        }

        // was it successful?
        if(state.success()) {
          // yay, nothing to do really
        } else {
          // throw an error
          std::stringstream error;
          error << "Auth failed: \"" << state.errordetails() << "\"";
          throw ProtocolError(error.str().c_str());
        }
      }
        // undefined message type :(
      else {
        std::stringstream error;

        error << "Received unexpected message type '" << type << "'; expected ";
        error << "Error or AuthState";

        throw ProtocolError(error.str().c_str());
      }
    });
  }



  /**
   * Sends a response to a previous request.
   *
   * @param response Message to respond with
   */
  void HmacChallengeHandler::sendMessage(google::protobuf::Message &response) {
    int written;

    // serialize message
    std::vector<std::byte> responseBytes;
    MessageSerializer::serialize(responseBytes, response);

    // send it
    written = this->client->write(responseBytes);

    if(written != responseBytes.size()) {
      LOG(ERROR) << "Couldn't write full message! (Wrote " << written << ", "
                 << "but total is " << responseBytes.size() << ")";
      return;
    }

    // done, I guess
    VLOG(1) << "Sent response: " << response.DebugString();
  }


  /**
   * Given a wire format message, attempts to decode the protocol buffer that is
   * contained within.
   *
   * @param outMessage Protocol message into which we deserialize
   * @param buffer Buffer containing message bytes; all fields that require it
   * are swapped to host byte order at this point.
   */
  void HmacChallengeHandler::decodeMessage(protoMessageType &outMessage,
                                           std::vector<std::byte> &buffer) {
    // get wire message struct
    auto *wire = reinterpret_cast<lichtenstein_message_t *>(buffer.data());

    // we should have at least as much in the vector as the payload size says
    if(wire->length > buffer.size()) {
      std::stringstream error;

      error << "Invalid message length (wire message indicates "
            << wire->length;
      error << " bytes of payload, but a total of " << buffer.size();
      error << " bytes were read from the client, including wire message)";

      throw ProtocolError(error.str().c_str());
    }

    // cool, we have enough data. try to decode it
    int realPayloadSize = std::min((size_t) wire->length, (buffer.size() -
                                                           sizeof(lichtenstein_message_t)));

    if(!outMessage.ParseFromArray(wire->payload, realPayloadSize)) {
      throw ProtocolError("Could not decode protobuf");
    }

    // neat, the message could be decoded. validate version
    if(outMessage.version() != lichtenstein_protocol_get_version()) {
      std::stringstream error;

      error << "Invalid protocol version (wire message is version 0x";
      error << std::hex << outMessage.version()
            << ", whereas the protocol lib is 0x";
      error << std::hex << lichtenstein_protocol_get_version() << ")";

      throw ProtocolError(error.str().c_str());
    }
  }

  /**
   * Reads a message from the client; this will either throw an exception or
   * invoke the specified success closure.
   *
   * @param success Closure to run when a valid message has been received.
   */
  void HmacChallengeHandler::readMessage(
          const std::function<void(protoMessageType &)> &success) {
    std::vector<std::byte> received;
    int read;

    // read the wire header
    const size_t wireHeaderLen = sizeof(lichtenstein_message_t);
    read = this->client->read(received, wireHeaderLen);

    if(read != wireHeaderLen) {
      std::stringstream error;

      error << "Protocol error: expected to read ";
      error << wireHeaderLen << " bytes, got " << read;
      error << " bytes instead!";

      throw ProtocolError(error.str().c_str());
    }

    // byteswap all fields that need it
    void *data = received.data();
    auto *msg = reinterpret_cast<lichtenstein_message_t *>(data);

    msg->length = ntohl(msg->length);

    VLOG(2) << "Message contains " << msg->length << " more bytes";

    // read the rest of the payload now (size checking happens during decode)
    read = this->client->read(received, msg->length);
    VLOG(2) << "Read " << received.size() << " total bytes from client "
            << this->client;

    lichtenstein::protocol::Message message;
    this->decodeMessage(message, received);

    // message is valid, so run callback
    success(message);
  }

  /**
   * Handles an Error message, by converting it into an exception.
   *
   * @param message Received message that contains an Error as payload
   */
  void HmacChallengeHandler::handleError(const protoMessageType &message) {
    Error error;
    if(!message.payload().UnpackTo(&error)) {
      throw ProtocolError("Failed to unpack Error");
    }

    throw ProtocolError(error.DebugString().c_str());
  }


  /**
   * Calculates the correct HMAC response.
   *
   * The HMAC is comprised of 16 raw bytes of the node UUID, followed directly
   * by the nonce.
   *
   * @param outBuffer Buffer to which the resultant digest is written
   * @param fn Hash function to use
   * @param nonce Nonce to include in the hash
   */
  void HmacChallengeHandler::doHmac(std::vector<std::byte> &outBuffer,
                                    const EVP_MD *fn,
                                    const std::vector<std::byte> &nonce) {
    CHECK_NOTNULL(fn);

    // reserve the amount needed for the digest in the output buffer
    unsigned int digestSz = EVP_MD_size(fn);

    outBuffer.reserve(digestSz);
    std::fill(outBuffer.begin(), outBuffer.begin() + digestSz, std::byte(0));

    auto outBufPtr = outBuffer.data();

    // set up context
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    // load the key
    HMAC_Init_ex(&ctx, this->hmacSecret.data(), this->hmacSecret.length(), fn,
                 nullptr);

    // insert the UUID bytes
    auto uuidBytes = this->uuid.as_bytes();
    HMAC_Update(&ctx, reinterpret_cast<const unsigned char *>(uuidBytes.data()),
                uuidBytes.size());

    // then, update hash with the nonce
    HMAC_Update(&ctx, reinterpret_cast<const unsigned char *>(nonce.data()),
                nonce.size());

    // we're done, produce the result
    HMAC_Final(&ctx, reinterpret_cast<unsigned char *>(outBufPtr), &digestSz);
    HMAC_CTX_cleanup(&ctx);
  }

  /**
   * Generates random data and writes it into the specified vector.
   *
   * @param outBuffer Vector to receive random data
   * @param bytes Number of bytes to generate
   */
  void HmacChallengeHandler::generateRandom(std::vector<std::byte> &outBuffer,
                                            size_t bytes) {
    int err = 0;

    // reserve space in the output buffer
    outBuffer.reserve(bytes);
    std::fill(outBuffer.begin(), outBuffer.begin() + bytes, std::byte(0));

    auto outBufPtr = reinterpret_cast<unsigned char *>(outBuffer.data());

    // generate random data
    err = RAND_bytes(outBufPtr, bytes);

    if(err != 1) {
      throw OpenSSLError("RAND_bytes() failed");
    }
  }
}