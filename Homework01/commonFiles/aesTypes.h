/**
 * @file aesTypes.h
 * @author xmelkov
 */


#ifndef AES_TYPES_GUARD
#define AES_TYPES_GUARD

/**
 * @def AES_KEY_LENGTH
 * Defines size (in bytes) of AES symmetric key.
 * Since 128-key is used, 16 is the required length (128/8)
 */
#define AES_KEY_LENGTH 16

/**
 * @def AES_BLOCK_SIZE
 * Defines size (in bytes) of block of data processed, that AES can process (which is also 128 bits)
 */
#define AES_BLOCK_SIZE 16

/**
 * @def SHA512_BLOCK_SIZE
 * Specifies size (in bytes) of output of SHA512 hash function
 */
#define SHA512_OUTPUT_SIZE 64

/**
 * @def PERSONALIZATION_STRING
 * A phrase required to generate aes keys.
 */
#define PERSONALIZATION_STRING "random string (passphrase) used for generating AES key"

//	STL includes

#include <array>

#include <vector>

using AESKey = std::array<unsigned char, AES_KEY_LENGTH>;
using AESData = std::vector<unsigned char>;
using SHA512output = std::array<unsigned char, SHA512_OUTPUT_SIZE>;

#endif // !AES_TYPES_GUARD