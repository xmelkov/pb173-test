#include <iostream>

#include "encryption.h"

int main()
{
	auto seed = initializeAESKeySeed(std::string(PERSONALIZATION_STRING));
	
	AESKey key = generateRandomAESKey(seed);


	freeAESKeySeed(&seed);
	return 0;
}
