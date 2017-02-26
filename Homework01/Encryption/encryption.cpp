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
static void fillAESBlock(AESData & block, const AESData::size_type offset);

/**
 * @brief Reads whole file as byte vector.
 * @param inputFile File, where input data is readed
 * @param aesData Vector reference. This parameter is filled with values during this method
 * @return Integer value: \p (-1) in case error occured during input, non-negative integer
 * otherwise, which represents value \p length % [\p AES_BLOCK_SIZE](@ref AES_BLOCK_SIZE)-
 * (required for alignment)
 */
static int aesInput(std::ifstream & inputFile, AESData & aesData);

static void fillAESBlock(AESData & block, const AESData::size_type offset)
{
	const AESData::size_type length = block.size();
	for (
			AESData::size_type position = length - offset;
			position < length; ++position
		)
	{
		block[position] = offset;
	}
}

static int aesInput(std::ifstream & inputFile, AESData & aesData)
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

	return (!inputFile.bad()) ? 0 : -1;
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
	unsigned char offset = 0;

	if (!inputFile.is_open() || (offset = static_cast<unsigned int>(aesInput(inputFile,data) < 0)))
	{
		std::cerr << "Unable to read \'" << sourceFilePath << "\' file" << std::endl;
		return false;
	}
	inputFile.close();

	if (offset)
	{
		fillAESBlock(data, AES_BLOCK_SIZE - offset);
	}

	//	Encryption itself
	mbedtls_aes_context aesContext;
	mbedtls_aes_init(&aesContext);

	mbedtls_aes_setkey_enc(&aesContext, key.data(), constexpr(8 * AES_KEY_LENGTH) );
	//mbedtls_aes_crypt_cbc(&aesContext,MBEDTLS_AES_ENCRYPT,)

	mbedtls_aes_free(&aesContext);
	return true;
}

