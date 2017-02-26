#include "encryption.h"

#include <stdexcept>

#include "..\libExcerpt\mbedtls\entropy.h"
#include "..\libExcerpt\mbedtls\ctr_drbg.h"

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
