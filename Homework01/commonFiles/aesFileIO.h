/**
 * @file aesFileIO.h
 * @author xmelkov
 */

#ifndef AES_FILE_IO_GUARD
#define AES_FILE_IO_GUARD

/**
* @def ENC_FILE_EXTENSION
* Specifies file extension for encryption output
*/
#define ENC_FILE_EXTENSION ".crypt"

/**
* @def DEC_FILE_EXTENSION
* Specifies file extension for decryption output
*/
#define DEC_FILE_EXTENSION ".txt"

/**
* @def KEY_FILE_EXTENSION
* Specifies file extension for key output
*/
#define KEY_FILE_EXTENSION ".key"

/**
* @def SIG_FILE_EXTENSION
* Specifies file extension for hash output
*/
#define SIG_FILE_EXTENSION ".sig"

#include ".\aesTypes.h"

//!<	Enum class. Specifies output mode of data used during encryption/decryption process
enum class OutputMode
{
	//!<	Encrypted data option (encryption)
	OUTPUT_ENCRYPTED,

	//!<	Decrypted data option (decryption)
	OUTPUT_DECRYPTED,

	//!<	Key data option (encryption)
	OUTPUT_KEY,

	//!<	Hash/signature option(encryption)
	OUTPUT_SIGNATURE
};

/**
 * @brief Reads whole file as byte vector.
 * @param inputFile File, where input data is readed
 * @param aesData Vector reference. This parameter is filled with values during this method
 * @return Integer value: \p (-1) in case error occured during input, non-negative integer
 * otherwise, which represents value \p length % [\p AES_BLOCK_SIZE](@ref AES_BLOCK_SIZE)-
 * (required for alignment)
 */
int aesInput(std::ifstream & inputFile, AESData & aesData);

/**
 * @brief prints binary(enc,dec)/hexadecimal(hash,key) output to file with specified extension
 * @param outputPath Path to the output file (does not have to have correct extension)
 * @param type Specifies type of data provided
 * @param first Beginning of the output data
 * @param last End of the output data
 * @throw std::invalid_argument in case if type contains invalid value
 * @throw std::domain_error if for some reason output file could not be opened
 */
void aesOutput(
	std::string & outputPath,
	OutputMode type,
	const unsigned char * first,
	const unsigned char * last
);

#endif // !AES_FILE_IO_GUARD
