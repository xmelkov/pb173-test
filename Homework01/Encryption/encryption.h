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

/**
 * @def ENC_FILE_EXTENSION
 * Specifies file extension for encryption output
 */
#define ENC_FILE_EXTENSION ".crypt"

 /**
  * @def DEC_FILE_EXTENSION
  * Specifies file extension for decryption output
  */
#define DEC_FILE_EXTENSION ".txt"

 /**
  * @def KEY_FILE_EXTENSION
  * Specifies file extension for key output
  */
#define KEY_FILE_EXTENSION ".key"
 
 /**
  * @def SIG_FILE_EXTENSION
  * Specifies file extension for hash output
  */
#define SIG_FILE_EXTENSION ".sig"

//	mbedTLS includes
#include "..\libExcerpt\mbedtls\ctr_drbg.h"

//	STL includes

#include <array>

#include <string>

#include <vector>

using AESKey = std::array<unsigned char, AES_KEY_LENGTH>;
using AESData = std::vector<unsigned char>;

/**
 * @brief Initializes seed, used for generating AES keys
 * @param passphrase Sample data used to create seed
 * @return mbedtls structure-Deterministic Random Number Generator,
 * which serves as seed to generate AES keys
 * @throw std::domain_error in case if seed initialization failed
 * @note After done working with mbedtls structure, resource should be freed
 */
mbedtls_ctr_drbg_context initializeAESKeySeed(const std::string & passphrase);

/**
 * @brief Generates AES key for file encrypting
 * @param seed Seed used in rng
 * @return Generated key
 * @throw std::domain_error in case if random number generation failed
 */
AESKey generateRandomAESKey(mbedtls_ctr_drbg_context & seed);

/**
 * Resource deallocation
 * @param seed Seed
 */
inline void freeAESKeySeed(mbedtls_ctr_drbg_context * seed)
{
	mbedtls_ctr_drbg_free(seed);
}

/**
 * @brief main-encrypting function of the module
 * @param key 128-bit encryption key
 * @param sourceFilePath Path to source file (to be encrypted)
 * @param outputFilePath Path to output file (encryption result)
 * @param passphrase Sample string used to generate keys (not initialize )
 * @return Bool value, representing success of the encryption process
 */
bool encryptFile(
	const AESKey & key, 
	const std::string & sourceFilePath,
	std::string & outputFilePath,
	const std::string & passphrase
);

#endif // !ENCRYPTION_GUARD