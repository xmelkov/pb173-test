#include <iomanip>
#include <iostream>
#include <string>

#include "encryption.h"

int main()
{
	for (unsigned int i = 0; i < 256; ++i)
	{
		std::cout << std::hex << std::setw(2) << std::setfill('0') << i << std::endl;
	}
	
	/*auto seed = initializeAESKeySeed(std::string(PERSONALIZATION_STRING));
	AESKey key = generateRandomAESKey(seed);

	//std::cout << "Hello World!" << std::endl;
	freeAESKeySeed(&seed);*/
	return 0;
}
