//
// Created by Tristan Seifert on 2019-08-18.
//

#ifndef LIBLICHTENSTEIN_WIREMESSAGE_H
#define LIBLICHTENSTEIN_WIREMESSAGE_H

#include <cstdint>

// pack structs
#pragma pack(push, 1)

/**
 * Represents the basic format of a Lichtenstein API message on the wire.
 */
typedef struct lichtenstein_message {
  // number of bytes of payload
  uint32_t length;

  // protobuf (this is the shared/Message type)
  char payload[];
} lichtenstein_message_t;

// restore packing mode
#pragma pack(pop)

#endif //LIBLICHTENSTEIN_WIREMESSAGE_H
