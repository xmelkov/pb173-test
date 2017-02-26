#include <iostream>

#include "encryption.h"

int main(int argc, const char ** argv)
{
	if (argc == 1)
	{
		std::cerr << "Requires source path as command line argument" << std::endl;
		return 1;
	}
	auto seed = initializeAESKeySeed(std::string(PERSONALIZATION_STRING));
	
	AESKey key = generateRandomAESKey(seed);

	std::cout << "Enter a passphrase" << std::endl;
	std::string passphrase;
	std::cin >> passphrase;

	encryptFile(key, std::string(argv[1]),std::string(""), std::string(""), std::string(""),passphrase);

	freeAESKeySeed(&seed);
	return 0;
}
