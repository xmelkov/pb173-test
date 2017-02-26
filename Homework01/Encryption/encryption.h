/**
 * @file encryption.h
 * @author xmelkov
 */

#ifndef ENCRYPTION_GUARD
#define ENCRYPTION_GUARD

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
 * @def PERSONALIZATION_STRING
 * A phrase required to generate aes keys.
 */
#define PERSONALIZATION_STRING "random string (passphrase) used for generating AES key"

#include <array>

#include <iostream>

#include <string>

using AESKey = std::array<unsigned char, AES_KEY_LENGTH>;
using AESData = AESKey;

/**
 * Generates AES key for file encrypting
 * @throw std::domain_error in case if seed initialization/random number generation failed
 * @return Generated key
 */
AESKey generateRandomAESKey();


#endif // !ENCRYPTION_GUARD