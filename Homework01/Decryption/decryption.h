/**
* @file decryption.h
* @author xmelkov
*/

#ifndef DECRYPTION_GUARD
#define DECRYPTION_GUARD

#include ".\aesTypes.h"


/**
 * @brief Compares SHA512 hash of contents of the file, with its signature.
 * @param contents Contents of encrypted file
 * @param signatureFile Short file, which should contain hash value of the contents of the file
 * @return Verification result
 */
bool verifyFile(const AESData & contents, const std::string & signatureFile);


#endif
