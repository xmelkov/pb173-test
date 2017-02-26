/**
 * @file encryption.h
 * @author xmelkov
 */

#ifndef ENCRYPTION_GUARD
#define ENCRYPTION_GUARD

/**
* @def AES_KEY_LENGTH
* Defines length (number of bytes) of AES symmetric key.
* Since 128-key is used, 16 is the required length (128/8)
*/
#define AES_KEY_LENGTH 16

/**
 * @def PERSONALIZATION_STRING
 * A phrase required to generate aes keys.
 */
#define PERSONALIZATION_STRING "random string (passphrase) used for generating AES key"

#include <array>
#include <iostream>

using AESKey = std::array<unsigned char, AES_KEY_LENGTH>;

/**
 * Generates AES key for file encrypting
 * @throw std::domain_error in case if seed initialization/random number generation failed
 * @return Generated key
 */
AESKey generateRandomAESKey();



#endif // !ENCRYPTION_GUARD