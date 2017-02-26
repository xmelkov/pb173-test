/**
 * @file encryption.h
 * @author xmelkov
 */

#ifndef ENCRYPTION_GUARD
#define ENCRYPTION_GUARD

//	Required for std::string type
#include <string>

//	Required for IO encrypting operations
#include "..\commonFiles\aesFileIO.h"

//	Required for key generation
#include "..\libExcerpt\mbedtls\ctr_drbg.h"
 
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
 * @param keyFilePath Path to output file, where encryption key is stored
 * @param hashFilePath Path to output file, where hash of the file is stored
 * @param passphrase Sample string used to generate keys (not to initialize seed)
 * @return Bool value, representing success of the encryption process
 */
bool encryptFile(
	const AESKey & key,
	const std::string & sourceFilePath,
	std::string & outputFilePath,
	std::string & keyFilePath,
	std::string & hashFilePath,
	const std::string & passphrase
);

#endif // !ENCRYPTION_GUARD