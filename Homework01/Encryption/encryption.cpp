#include "encryption.h"

#include <stdexcept>

#include "..\libExcerpt\mbedtls\entropy.h"
#include "..\libExcerpt\mbedtls\ctr_drbg.h"

/**
* @brief Fills single block with value representing, how many padded bytes are needed (PKCS#7 padding)
* @param block Block of input data, to be updated
* @param length Number of readed bytes. This parameter should be always lesser than
* [block size](@ref AES_KEY_LENGTH)
*/
static void fillAESBlock(AESData & block, const unsigned int length);

AESKey generateRandomAESKey()
{
	AESKey key;

	mbedtls_ctr_drbg_context ctrDbgContext;
	mbedtls_entropy_context entropyContext;

	char * passhrase = PERSONALIZATION_STRING;		//	Initialization
	mbedtls_entropy_init(&entropyContext);
	mbedtls_ctr_drbg_init(&ctrDbgContext);

	if (
		mbedtls_ctr_drbg_seed(
				&ctrDbgContext,
				mbedtls_entropy_func,
				&entropyContext,
				(unsigned char *) passhrase,
				strlen(passhrase)
			) ||
		mbedtls_ctr_drbg_random(
				&ctrDbgContext,
				key.data(),
				AES_KEY_LENGTH
			)
		)
	{
		throw std::domain_error("Error generating AES key");
	}
	mbedtls_entropy_free(&entropyContext);		//	Cleanup
	mbedtls_ctr_drbg_free(&ctrDbgContext);

	return key;									/*	Return value optimization should be applied here 
													(supposing usage of c++11 or newer)*/
}

static void fillAESBlock(AESData & block, unsigned int length)
{
	const unsigned int fillValue = AES_KEY_LENGTH - length;
	
	for (; length < AES_BLOCK_SIZE; ++length)
	{
		block[length] = fillValue;
	}
}
