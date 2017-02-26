#include "encryption.h"

//	Required for std::find
#include <algorithm>

//	Required for setw/setfill
#include <iomanip>

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

//	Required for AES encryption
#include "..\libExcerpt\mbedtls\aes.h"


enum class OutputMode
{
	OUTPUT_ENCRYPTED,
	OUTPUT_DECRYPTED,
	OUTPUT_KEY,
	OUTPUT_SIGNATURE
};

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

/**
 * Removes file extension (if there is one) and appends new one
 * @param filePath Original filepath
 * @param extension New file extension
 */
static void modifyFileExtension(std::string & filePath, const std::string & extension);

static void aesOutput(std::string & outputPath, OutputMode type);

static void fillAESBlock(AESData & block, const AESData::size_type offset)
{
	const AESData::size_type length = block.size();
	for (
			AESData::size_type position = length - offset;
			position < length; ++position
		)
	{
		block[position] = static_cast<unsigned char>(offset);
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

static void modifyFileExtension(std::string & filePath, const std::string & extension)
{
	auto it = filePath.end();

	--it;			//	Extension shouldn't be empty

	while (*it != '.' && it != filePath.begin())
	{
		--it;
	}

	if (it != filePath.begin())		//	If filpepath contains extension
	{
		if (extension[0] == '.')
		{
			++it;
		}

		filePath.erase(it, filePath.end());
	}

	filePath += extension;
}

static void aesOutput(
	std::string & outputPath, 
	OutputMode type, 
	const unsigned char * first, 
	const unsigned char * last
)
{
	std::string extension;
	switch (type)
	{
	case OutputMode::OUTPUT_ENCRYPTED:
		extension = std::string(ENC_FILE_EXTENSION);
		break;
	case OutputMode::OUTPUT_DECRYPTED:
		extension = std::string(DEC_FILE_EXTENSION);
		break;
	case OutputMode::OUTPUT_KEY:
		extension = std::string(KEY_FILE_EXTENSION);
		break;
	case OutputMode::OUTPUT_SIGNATURE:
		extension = std::string(SIG_FILE_EXTENSION);
		break;
	default:
		throw std::invalid_argument("Output mode contains invalid value");
	}

	modifyFileExtension(outputPath, extension);
	std::ofstream outputFile;
	if (type == OutputMode::OUTPUT_DECRYPTED || type == OutputMode::OUTPUT_ENCRYPTED)
	{
		outputFile.open(outputPath, std::ios::binary | std::ios::out);
		std::copy(first, last, std::ostream_iterator<unsigned char>(outputFile));
	}
	else
	{
		outputFile.open(outputPath, std::ios::binary);
		while (first != last)
		{
			std::cout << std::hex << std::setfill('0') << std::setw(2) << *first++;
		}
	}

	if (!outputFile.is_open())
	{
		throw std::domain_error("Unable to perform output operation-failed to open file");
	}
	
}

mbedtls_ctr_drbg_context initializeAESKeySeed(const std::string & passphrase)
{
	mbedtls_ctr_drbg_context ctrDbgContext;
	mbedtls_entropy_context entropyContext;

	mbedtls_entropy_init(&entropyContext);
	mbedtls_ctr_drbg_init(&ctrDbgContext);

	if (
		mbedtls_ctr_drbg_seed(
				&ctrDbgContext,
				mbedtls_entropy_func,
				&entropyContext,
				(const unsigned char *) passphrase.c_str(),
				passphrase.size()
			)
		)
	{
		throw std::domain_error("Unable to initialize seed");
	}
	mbedtls_entropy_free(&entropyContext);		//	Cleanup
	return ctrDbgContext;
}

AESKey generateRandomAESKey(mbedtls_ctr_drbg_context & seed)
{
	AESKey key;
	if (
		mbedtls_ctr_drbg_random(
				&seed,
				key.data(),
				AES_KEY_LENGTH
			)
		)
	{
		throw std::domain_error("Error generating AES key");
	}
	return key;									/*	Return value optimization should be applied here 
													(supposing usage of c++11 or newer)*/
}

bool encryptFile(
	const AESKey & key, 
	const std::string & sourceFilePath, 
	std::string & outputFilePath,
	const std::string & passphrase
)
{
	//	File input
	std::ifstream inputFile(sourceFilePath, std::ios::in | std::ios::binary);
	AESData rawData, encryptedData;
	unsigned char offset = 0;

	if (!inputFile.is_open() || (offset = static_cast<unsigned int>(aesInput(inputFile,rawData) < 0)))
	{
		std::cerr << "Unable to read \'" << sourceFilePath << "\' file" << std::endl;
		return false;
	}
	inputFile.close();

	if (offset)
	{
		fillAESBlock(rawData, AES_BLOCK_SIZE - offset);
	}

	//	Encryption part
	encryptedData.resize(rawData.size());			//	Allocates sufficient space for output

	mbedtls_aes_context aesContext;					
	mbedtls_aes_init(&aesContext);

	mbedtls_aes_setkey_enc(&aesContext, key.data(), constexpr(8 * AES_KEY_LENGTH) );
	mbedtls_aes_crypt_cbc(
		&aesContext,
		MBEDTLS_AES_ENCRYPT,
		static_cast<size_t>(rawData.size() / AES_BLOCK_SIZE),
		0,
		rawData.data(),
		encryptedData.data()
	);

	mbedtls_aes_free(&aesContext);

	//	File output part
	if (outputFilePath.empty())
	{
		outputFilePath = std::move(sourceFilePath);
	}
	modifyFileExtension(outputFilePath, std::string(".crypt"));
	

	return true;
}

