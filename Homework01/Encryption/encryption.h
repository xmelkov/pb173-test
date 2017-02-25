#ifndef ENCRYPTION_GUARD
#define ENCRYPTION_GUARD

#define AES_KEY_LENGTH 16
#define SHA512_BLOCK_LENGTH 64
#define PERSONALIZATION_STRING "random string (passphrase) used for generating AES key"

#include <array>

using AESKey = std::array<unsigned char, AES_KEY_LENGTH>;
using SHA512Block = std::array<unsigned char, SHA512_BLOCK_LENGTH>;

AESKey generateRandomKey();

#endif // !ENCRYPTION_GUARD