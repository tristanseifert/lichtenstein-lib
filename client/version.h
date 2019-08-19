//
// Created by Tristan Seifert on 2019-08-15.
//

#ifndef LIBLICHTENSTEIN_VERSION_H
#define LIBLICHTENSTEIN_VERSION_H

/**
 * Returns the library version.
 */
unsigned int lichtenstein_client_get_version(void);

// Global version strings
extern const char *gVERSION;
extern const char *gVERSION_SHORT;
extern const char *gVERSION_HASH;

#endif //LIBLICHTENSTEIN_VERSION_H
