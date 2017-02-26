#include <iomanip>
#include <iostream>
#include <string>

#include "encryption.h"

int main()
{
	auto seed = initializeAESKeySeed(std::string(PERSONALIZATION_STRING));
	AESKey key = generateRandomAESKey(seed);

	//std::cout << "Hello World!" << std::endl;
	freeAESKeySeed(&seed);
	return 0;
}
