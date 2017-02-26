#include <iostream>

#include "encryption.h"

static inline void help()
{
	std::cout << "Encrypt <source-file> [key] [output-file] [key-output] [hash-output] [passphrase]\n" << std::endl
		<< "<source-file> Input file to encrypt-obligatory parameter" << std::endl
		<< "[key]         Hexadecimal key string. Should be 128 bits long (16 characters)" << std::endl
		<< "[output-file] Path to the output-encrypted file." << std::endl
		<< "[hash-output] Path to the file, containing SHA512 hash of encrpyted data" << std::endl
		<< "[passphrase]  short user-entered string used for generating key." << std::endl;
}

int main(int argc, const char ** argv)
{
	if (argc == 1)
	{
		std::cerr << "Requires source path as command line argument. "
				  << "For further details type Encrypt -h" << std::endl;
		return 1;
	}
	if (argc == 2 && !(strcmp(argv[1],"-h")))
	{
		help();
		return 0;
	}
	std::string sKey("");
	std::string outputFile("");
	std::string outputKeyFile("");
	std::string hashFile("");
	std::string passphrase("");

	AESKey key;

	switch (argc)
	{
	moreThanSix:
	case 7:
		passphrase = argv[6];
	case 6:
		hashFile = argv[5];
	case 5:
		outputKeyFile = argv[4];
	case 4:
		outputFile = argv[3];
	case 3:
		sKey = argv[2];
	case 2:
		break;
	default:
		goto moreThanSix;
	}

	auto seed = initializeAESKeySeed(std::string(PERSONALIZATION_STRING));
	
	key = (sKey.empty()) ? generateRandomAESKey(seed) : keyFromString(sKey);

	if (passphrase.empty())
	{
		std::cout << "Enter a passphrase" << std::endl;
		std::cin >> passphrase;
	}
	encryptFile(key, std::string(argv[1]),outputFile, outputKeyFile, hashFile, passphrase);

	freeAESKeySeed(&seed);
	return 0;
}
