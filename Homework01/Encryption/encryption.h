#ifndef ENCRYPTION_GUARD
#define ENCRYPTION_GUARD

#define AES_KEY_LENGTH 16
#define SHA512_BLOCK_LENGTH 64
#define PERSONALIZATION_STRING "random string (passphrase) used for generating AES key"

#include <array>
#include <iostream>

using AESKey = std::array<unsigned char, AES_KEY_LENGTH>;
using SHA512Block = std::array<unsigned char, SHA512_BLOCK_LENGTH>;

AESKey generateRandomAESKey();
unsigned int alignSHA512Block(SHA512Block & sha512block, const unsigned int blockLength);


#endif // !ENCRYPTION_GUARD