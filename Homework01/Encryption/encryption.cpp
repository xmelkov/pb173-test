#include "encryption.h"


//	Required for input flags
#include <ios>

//	Required for console output
#include <iostream>

//	Required for file input
#include <fstream>

//	Required for exception handling in case of bad key generation
#include <stdexcept>

//	Required for generating AES key
#include "..\libExcerpt\mbedtls\entropy.h"
#include "..\libExcerpt\mbedtls\ctr_drbg.h"

//	Required for AES encryption
#include "..\libExcerpt\mbedtls\aes.h"

/**
* @brief Fills single block with value representing, how many padded bytes are needed (PKCS#7 padding)
* @param block Block of input data, to be updated
* @param length Number of readed bytes. This parameter should be always lesser than
* [block size](@ref AES_KEY_LENGTH)
*/
static void fillAESBlock(AESData & block, const unsigned int length);

/**
 * @brief Reads whole file as byte vector.
 * @param inputFile File, where input data is readed
 * @param aesData Vector reference. This parameter is filled with values during this method
 * @return Bool value representing, whether operation was successful
 */
static bool aesInput(std::ifstream & inputFile, std::vector<unsigned char> & aesData);

static void fillAESBlock(AESData & block, unsigned int length)
{
	const unsigned int fillValue = AES_KEY_LENGTH - length;

	for (; length < AES_BLOCK_SIZE; ++length)
	{
		block[length] = fillValue;
	}
}

static bool aesInput(std::ifstream & inputFile, std::vector<unsigned char> & aesData)
{
	unsigned int position = 0;
	
	while (inputFile.good())
	{
		aesData.resize(aesData.size() + AES_BLOCK_SIZE);
		for (unsigned int i = 0; i < AES_BLOCK_SIZE && inputFile.good(); ++i)
		{
			inputFile >> aesData[position];
			++position;
		}
	}

	return !inputFile.bad();
}


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

bool encryptFile(const AESKey & key, const std::string & sourceFilePath)
{
	//	File input
	std::ifstream inputFile(sourceFilePath, std::ios::in | std::ios::binary);
	AESData data;

	if (!(inputFile.is_open() && aesInput(inputFile,data)))
	{
		std::cerr << "Unable to read \'" << sourceFilePath << "\' file" << std::endl;
		return false;
	}
	inputFile.close();

	//	Encryption itself
	mbedtls_aes_context aesContext;
	mbedtls_aes_init(&aesContext);

	mbedtls_aes_setkey_enc(&aesContext, key.data(), constexpr(8 * AES_KEY_LENGTH) );

	mbedtls_aes_free(&aesContext);
	return true;
}

