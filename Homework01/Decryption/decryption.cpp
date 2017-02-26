#include ".\decryption.h"

//	Required for file input
#include "..\commonFiles\aesFileIO.h"

//	Required for the hash function
#include "..\libExcerpt\mbedtls\sha512.h"

//	Required for std::equal
#include <algorithm>

//	Required for file input
#include <fstream>

//	Required for error handling
#include <stdexcept>

bool verifyFile(const AESData & contents, const std::string & signatureFilePath)
{
	SHA512output hash1 = {};
	mbedtls_sha512(contents.data(), static_cast<size_t>(contents.size()), hash1.data(), 0);
	SHA512output hash2 = {};

	std::ifstream hashInputFile;
	hashInputFile.open(signatureFilePath, std::ios::in);
	if (!hashInputFile.is_open())
	{
		throw std::domain_error("Unable to read file signature and therefore verify file");
	}
	
	std::string hashString("");
	hashString.resize(SHA512_OUTPUT_SIZE);

	hashInputFile.getline(&hashString[0], constexpr(2*SHA512_OUTPUT_SIZE));

	hashInputFile.close();
	
	hash2 = hashFromString(hashString);

	return std::equal(hash1.begin(), hash1.end(), hash2.begin());
}