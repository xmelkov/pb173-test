/**
 * @file aesFileIO.cpp
 * @author xmelkov
 */
#include ".\aesFileIO.h"

//	Required for setw/setfill + input flags
#include <iomanip>

//	Required for console output
#include <iostream>

//	Required for file input
#include <fstream>

//	Required for exception handling
#include <stdexcept>

//	Required for char functions
#include <cctype>

/**
 * Removes file extension (if there is one) and appends new one
 * @param filePath Original filepath
 * @param extension New file extension
 */
static void modifyFileExtension(std::string & filePath, const std::string & extension)
{
	auto it = filePath.end();

	--it;			//	Extension shouldn't be empty

	while (*it != '.' && it != filePath.begin())
	{
		--it;
	}

	if (it != filePath.begin())		//	If filepath contains extension
	{
		if (extension[0] != '.')
		{
			++it;
		}

		filePath.erase(it, filePath.end());
	}

	filePath += extension;
}


int aesInput(std::ifstream & inputFile, AESData & aesData)
{
	unsigned int position = 0;

	while (inputFile.good())
	{
		aesData.resize(aesData.size() + AES_BLOCK_SIZE);
		for (unsigned int i = 0; i < AES_BLOCK_SIZE && inputFile.good(); ++i)
		{
			aesData[position] = inputFile.get();
			++position;
		}
	}

	return (!inputFile.bad()) ? position % AES_BLOCK_SIZE : -1;
}


void aesOutput(
	std::string & outputPath,
	OutputMode type,
	const unsigned char * first,
	const unsigned char * last
)
{
	std::string extension;
	switch (type)				//	Extension pick
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

	modifyFileExtension(outputPath, extension);		//	Formats output filepath
	std::ofstream outputFile;
	if (type == OutputMode::OUTPUT_DECRYPTED || type == OutputMode::OUTPUT_ENCRYPTED)
	{
		outputFile.open(outputPath, std::ios::binary | std::ios::out | std::ios::trunc);
		if (!outputFile.is_open())
		{
			throw std::domain_error("Unable to perform output operation-failed to open file");
		}
		while (first != last)
		{
			outputFile << *first++;
		}
	}
	else
	{
		outputFile.open(outputPath, std::ios::out | std::ios::trunc);
		if (!outputFile.is_open())
		{
			throw std::domain_error("Unable to perform output operation-failed to open file");
		}
		while (first != last)
		{
			outputFile << std::hex << std::setfill('0')
				<< std::setw(2) << ((*first) & 0xff);
			++first;
		}
	}
	outputFile << std::endl;
	outputFile.close();
}

AESKey keyFromString(std::string & sKey)
{
	if (sKey.size() > constexpr(AES_KEY_LENGTH * 2))
	{
		sKey.resize(constexpr(AES_KEY_LENGTH * 2));
	}
	AESKey newKey = {};
	AESKey::size_type keyIndex = constexpr(AES_KEY_LENGTH - 1);
	bool flag = true;
	for (std::string::size_type i = sKey.size() - 1; 
		i < constexpr(AES_KEY_LENGTH * 2) && isxdigit(sKey[i]) && 
		keyIndex < AES_KEY_LENGTH ; --i)
	{
		unsigned char value = sKey[i];
		value -= isalpha(sKey[i]) ? ((isupper(sKey[i]) ? 'A' : 'a')) - 10 : '0';
		newKey[keyIndex] |= ((flag) ? 1 : 16) * value;
		if (!flag) { --keyIndex; }
		flag = !(flag);
	}
	return newKey;
}
