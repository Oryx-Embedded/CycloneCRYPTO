/**
 * @file pkcs5_decrypt.c
 * @brief PKCS #5 decryption routines
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkix/pkcs5_common.h"
#include "pkix/pkcs5_decrypt.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cbc.h"
#include "mac/hmac.h"
#include "kdf/pbkdf.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS5_SUPPORT == ENABLED)


/**
 * @brief PKCS #5 decryption operation
 * @param[in] encryptionAlgoId Encryption algorithm identifier
 * @param[in] password NULL-terminated string containing the password
 * @param[in] ciphertext Pointer to the ciphertext data
 * @param[in] ciphertextLen Length of the ciphertext data, in bytes
 * @param[out] plaintext Pointer to the plaintext data
 * @param[out] plaintextLen Length of the plaintext data, in bytes
 * @return Error code
 **/

error_t pkcs5Decrypt(const X509AlgoId *encryptionAlgoId,
   const char_t *password, const uint8_t *ciphertext, size_t ciphertextLen,
   uint8_t *plaintext, size_t *plaintextLen)
{
   error_t error;

   //Check parameters
   if(encryptionAlgoId != NULL && password != NULL && ciphertext != NULL &&
      plaintext != NULL && plaintextLen != NULL)
   {
      //Check encryption algorithm identifier
      if(OID_COMP(encryptionAlgoId->oid.value, encryptionAlgoId->oid.length,
         PBES2_OID) == 0)
      {
         //Perform PBES2 decryption operation
         error = pkcs5DecryptPbes2(encryptionAlgoId, password, ciphertext,
            ciphertextLen, plaintext, plaintextLen);
      }
      else
      {
         //Perform PBES1 decryption operation
         error = pkcs5DecryptPbes1(encryptionAlgoId, password, ciphertext,
            ciphertextLen, plaintext, plaintextLen);
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief PBES1 decryption operation
 * @param[in] encryptionAlgoId Encryption algorithm identifier
 * @param[in] password NULL-terminated string containing the password
 * @param[in] ciphertext Pointer to the ciphertext data
 * @param[in] ciphertextLen Length of the ciphertext data, in bytes
 * @param[out] plaintext Pointer to the plaintext data
 * @param[out] plaintextLen Length of the plaintext data, in bytes
 * @return Error code
 **/

error_t pkcs5DecryptPbes1(const X509AlgoId *encryptionAlgoId,
   const char_t *password, const uint8_t *ciphertext, size_t ciphertextLen,
   uint8_t *plaintext, size_t *plaintextLen)
{
   error_t error;
   size_t i;
   size_t psLen;
   size_t passwordLen;
   uint8_t *k;
   uint8_t *iv;
   uint8_t dk[16];
   Pkcs5Pbes1Params pbes1Params;
   const HashAlgo *hashAlgo;
   const CipherAlgo *cipherAlgo;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   CipherContext *cipherContext;
#else
   CipherContext cipherContext[1];
#endif

   //Check the length of the encrypted data
   if(ciphertextLen == 0)
      return ERROR_DECRYPTION_FAILED;

   //Obtain the eight-octet salt S and the iteration count c
   error = pkcs5ParsePbes1Params(encryptionAlgoId->params.value,
      encryptionAlgoId->params.length, &pbes1Params);
   //Any error to report?
   if(error)
      return error;

   //Retrieve hash algorithm
   hashAlgo = pkcs5GetPbes1HashAlgo(encryptionAlgoId->oid.value,
      encryptionAlgoId->oid.length);
   //Invalid hash algorithm?
   if(hashAlgo == NULL)
      return ERROR_UNSUPPORTED_HASH_ALGO;

   //Retrieve cipher algorithm
   cipherAlgo = pkcs5GetPbes1CipherAlgo(encryptionAlgoId->oid.value,
      encryptionAlgoId->oid.length);
   //Invalid cipher algorithm?
   if(cipherAlgo == NULL)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //If the length in octets of the ciphertext C is not a multiple of eight,
   //output a decryption error and stop
   if((ciphertextLen % cipherAlgo->blockSize) != 0)
      return ERROR_DECRYPTION_FAILED;

   //Retrieve the length of the password
   passwordLen = osStrlen(password);

   //Apply the PBKDF1 key derivation function to the password P, the salt S,
   //and the iteration count c to produce a derived key DK of length 16 octets
   error = pbkdf1(hashAlgo, (uint8_t *) password, passwordLen,
      pbes1Params.salt.value, pbes1Params.salt.length,
      pbes1Params.iterationCount, dk, 16);
   //Any error to report?
   if(error)
      return error;

   //Separate the derived key DK into an encryption key K consisting of the
   //first eight octets of DK and an initialization vector IV consisting of
   //the next eight octets
   k = dk;
   iv = dk + 8;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the cipher context
   cipherContext = cryptoAllocMem(cipherAlgo->contextSize);
   //Failed to allocate memory?
   if(cipherContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Load encryption key K
   error = cipherAlgo->init(cipherContext, k, 8);

   //Check status code
   if(!error)
   {
      //Decrypt the ciphertext C with the underlying block cipher (DES or
      //RC2) in CBC mode under the encryption key K with initialization
      //vector IV to recover an encoded message EM
      error = cbcDecrypt(cipherAlgo, cipherContext, iv, ciphertext,
         plaintext, ciphertextLen);
   }

   //Erase cipher context
   cipherAlgo->deinit(cipherContext);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release previously allocated memory
   cryptoFreeMem(cipherContext);
#endif

   //Any error to report?
   if(error)
      return error;

   //Retrieve the length of the padding string PS
   psLen = plaintext[ciphertextLen - 1];

   //Ensure that psLen is between 1 and 8
   if(psLen < 1 || psLen > 8)
      return ERROR_DECRYPTION_FAILED;

   //Malformed padding?
   if(psLen > ciphertextLen)
      return ERROR_DECRYPTION_FAILED;

   //Verify padding string
   for(i = 0; i < psLen; i++)
   {
      //The padding string PS consists of psLen octets each with value psLen
      if(plaintext[ciphertextLen - i - 1] != psLen)
         return ERROR_DECRYPTION_FAILED;
   }

   //Strip padding bytes from the encoded message EM
   *plaintextLen = ciphertextLen - psLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief PBES2 decryption operation
 * @param[in] encryptionAlgoId Encryption algorithm identifier
 * @param[in] password NULL-terminated string containing the password
 * @param[in] ciphertext Pointer to the ciphertext data
 * @param[in] ciphertextLen Length of the ciphertext data, in bytes
 * @param[out] plaintext Pointer to the plaintext data
 * @param[out] plaintextLen Length of the plaintext data, in bytes
 * @return Error code
 **/

error_t pkcs5DecryptPbes2(const X509AlgoId *encryptionAlgoId,
   const char_t *password, const uint8_t *ciphertext, size_t ciphertextLen,
   uint8_t *plaintext, size_t *plaintextLen)
{
   error_t error;
   size_t i;
   size_t dkLen;
   size_t psLen;
   size_t passwordLen;
   uint8_t dk[32];
   uint8_t iv[16];
   Pkcs5Pbes2Params pbes2Params;
   const HashAlgo *hashAlgo;
   const CipherAlgo *cipherAlgo;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   CipherContext *cipherContext;
#else
   CipherContext cipherContext[1];
#endif

   //Check the length of the encrypted data
   if(ciphertextLen == 0)
      return ERROR_DECRYPTION_FAILED;

   //Obtain the salt S for the operation and the iteration count c for the
   //key derivation function
   error = pkcs5ParsePbes2Params(encryptionAlgoId->params.value,
      encryptionAlgoId->params.length, &pbes2Params);
   //Any error to report?
   if(error)
      return error;

   //Retrieve PRF hash algorithm
   hashAlgo = pkcs5GetPbes2HashAlgo(pbes2Params.keyDerivationFunc.prfAlgoId.value,
      pbes2Params.keyDerivationFunc.prfAlgoId.length);
   //Invalid hash algorithm?
   if(hashAlgo == NULL)
      return ERROR_UNSUPPORTED_HASH_ALGO;

   //Retrieve cipher algorithm
   cipherAlgo = pkcs5GetPbes2CipherAlgo(pbes2Params.encryptionScheme.oid.value,
      pbes2Params.encryptionScheme.oid.length);
   //Invalid cipher algorithm?
   if(cipherAlgo == NULL)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //Obtain the key length in octets, dkLen, for the derived key for the
   //underlying encryption scheme
   dkLen = pkcs5GetPbes2KeyLength(pbes2Params.encryptionScheme.oid.value,
      pbes2Params.encryptionScheme.oid.length);
   //Invalid key length?
   if(dkLen == 0)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //If the length in octets of the ciphertext C is not a multiple of the block
   //size, output a decryption error and stop
   if((ciphertextLen % cipherAlgo->blockSize) != 0)
      return ERROR_DECRYPTION_FAILED;

   //Check the length of the IV
   if(pbes2Params.encryptionScheme.iv.length != cipherAlgo->blockSize)
      return ERROR_DECRYPTION_FAILED;

   //Copy initialization vector
   osMemcpy(iv, pbes2Params.encryptionScheme.iv.value, cipherAlgo->blockSize);

   //Retrieve the length of the password
   passwordLen = osStrlen(password);

   //Apply the selected KDF function to the password P, the salt S, and the
   //iteration count c to produce a derived key DK of length dkLen octets
   error = pbkdf2(hashAlgo, (uint8_t *) password, passwordLen,
      pbes2Params.keyDerivationFunc.salt.value,
      pbes2Params.keyDerivationFunc.salt.length,
      pbes2Params.keyDerivationFunc.iterationCount, dk, dkLen);
   //Any error to report?
   if(error)
      return error;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the cipher context
   cipherContext = cryptoAllocMem(cipherAlgo->contextSize);
   //Failed to allocate memory?
   if(cipherContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Load encryption key DK
   error = cipherAlgo->init(cipherContext, dk, dkLen);

   //Check status code
   if(!error)
   {
      //Decrypt the ciphertext C with the underlying encryption scheme
      //under the derived key DK to recover a message M
      error = cbcDecrypt(cipherAlgo, cipherContext, iv, ciphertext,
         plaintext, ciphertextLen);
   }

   //Erase cipher context
   cipherAlgo->deinit(cipherContext);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release previously allocated memory
   cryptoFreeMem(cipherContext);
#endif

   //Any error to report?
   if(error)
      return error;

   //Retrieve the length of the padding string PS
   psLen = plaintext[ciphertextLen - 1];

   //Ensure that psLen is valid
   if(psLen < 1 || psLen > cipherAlgo->blockSize)
      return ERROR_DECRYPTION_FAILED;

   //Malformed padding?
   if(psLen > ciphertextLen)
      return ERROR_DECRYPTION_FAILED;

   //Verify padding string
   for(i = 0; i < psLen; i++)
   {
      //The padding string PS consists of psLen octets each with value psLen
      if(plaintext[ciphertextLen - i - 1] != psLen)
         return ERROR_DECRYPTION_FAILED;
   }

   //Strip padding bytes from the encoded message EM
   *plaintextLen = ciphertextLen - psLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PBES1 parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] pbes1Params Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs5ParsePbes1Params(const uint8_t *data, size_t length,
   Pkcs5Pbes1Params *pbes1Params)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //The PBES1 parameters are encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read salt
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The salt must be an eight-octet string
   if(tag.length != 8)
      return ERROR_INVALID_SYNTAX;

   //Save salt value
   pbes1Params->salt.value = tag.value;
   pbes1Params->salt.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read iteration count
   error = asn1ReadInt32(data, length, &tag, &value);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The iteration count must be a positive integer
   if(value < 0)
      return ERROR_INVALID_SYNTAX;

   //Save iteration count
   pbes1Params->iterationCount = value;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PBES2 parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] pbes2Params Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs5ParsePbes2Params(const uint8_t *data, size_t length,
   Pkcs5Pbes2Params *pbes2Params)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The PBES2 parameters are encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //KeyDerivationFunc identifies the underlying key derivation function. It
   //shall be an algorithm ID with an OID in the set PBES2-KDFs, which for
   //this version of PKCS #5 shall consist of id-PBKDF2
   error = pkcs5ParseKeyDerivationFunc(data, length, &n,
      &pbes2Params->keyDerivationFunc);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //EncryptionScheme identifies the underlying encryption scheme. It shall be
   //an algorithm ID with an OID in the set PBES2-Encs, whose definition is
   //left to the application
   error = pkcs5ParseEncryptionScheme(data, length, &n,
      &pbes2Params->encryptionScheme);
   //Any error to report?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse KeyDerivationFunc structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] keyDerivationFunc Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs5ParseKeyDerivationFunc(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs5KeyDerivationFunc *keyDerivationFunc)
{
   error_t error;
   Asn1Tag tag;

   //Read KeyDerivationFunc structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read the KDF algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save algorithm identifier
   keyDerivationFunc->kdfAlgoId.value = tag.value;
   keyDerivationFunc->kdfAlgoId.length = tag.length;

   //Check KDF algorithm identifier
   if(OID_COMP(keyDerivationFunc->kdfAlgoId.value,
      keyDerivationFunc->kdfAlgoId.length, PBKDF2_OID) != 0)
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse PBKDF2 parameters
   error = pkcs5ParsePbkdf2Params(data, length, keyDerivationFunc);
   //Any error to report?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PBKDF2 parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] keyDerivationFunc Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs5ParsePbkdf2Params(const uint8_t *data, size_t length,
   Pkcs5KeyDerivationFunc *keyDerivationFunc)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //The PBKDF2 parameters are encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //The 'salt' field specifies the salt value or the source of the salt value.
   //It shall either be an octet string or an algorithm ID with an OID in the
   //set PBKDF2-SaltSources, which is reserved for future versions of PKCS #5
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save salt value
   keyDerivationFunc->salt.value = tag.value;
   keyDerivationFunc->salt.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //The 'iterationCount' field specifies the iteration count
   error = asn1ReadInt32(data, length, &tag, &value);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The iteration count must be a positive integer
   if(value < 0)
      return ERROR_INVALID_SYNTAX;

   //Save iteration count
   keyDerivationFunc->iterationCount = value;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //The 'keyLength' field is the length in octets of the derived key
   error = asn1ReadInt32(data, length, &tag, &value);

   //This field is optional
   if(!error)
   {
      //The key length must be a positive integer
      if(value < 0)
         return ERROR_INVALID_SYNTAX;

      //Save key length
      keyDerivationFunc->keyLen = value;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;
   }
   else
   {
      //The 'keyLength' field is no present
      keyDerivationFunc->keyLen = 0;
   }

   //Check whether the 'prf' field is present
   if(length > 0)
   {
      //The PRF algorithm identifier is encapsulated within a sequence
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the PRF algorithm identifier
      error = asn1ReadOid(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Save algorithm identifier
      keyDerivationFunc->prfAlgoId.value = tag.value;
      keyDerivationFunc->prfAlgoId.length = tag.length;
   }
   else
   {
      //The default pseudorandom function is HMAC-SHA-1 (refer to RFC 8018,
      //section A.2)
      keyDerivationFunc->prfAlgoId.value = HMAC_WITH_SHA1_OID;
      keyDerivationFunc->prfAlgoId.length = sizeof(HMAC_WITH_SHA1_OID);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EncryptionScheme structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] encryptionScheme Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs5ParseEncryptionScheme(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs5EncryptionScheme *encryptionScheme)
{
   error_t error;
   Asn1Tag tag;

   //Read EncryptionScheme structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read the encryption algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save algorithm identifier
   encryptionScheme->oid.value = tag.value;
   encryptionScheme->oid.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //The parameters field for DES-CBC-Pad, DES-EDE3-CBC-Pad and AES-CBC-Pad
   //encryption schemes shall have type OCTET STRING specifying the
   //initialization vector for CBC mode
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save initialization vector
   encryptionScheme->iv.value = tag.value;
   encryptionScheme->iv.length = tag.length;

   //Successful processing
   return NO_ERROR;
}

#endif
