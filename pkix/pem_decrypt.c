/**
 * @file pem_decrypt.c
 * @brief PEM file decryption
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
#include "pkix/pem_decrypt.h"
#include "pkix/pkcs5_decrypt.h"
#include "pkix/pkcs8_key_parse.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cbc.h"
#include "hash/md5.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief PEM private key decryption
 * @param[in] input Pointer to the encrypted private key (PEM format)
 * @param[in] inputLen Length of the encrypted private key
 * @param[in] password NULL-terminated string containing the password
 * @param[out] output Pointer to decrypted private key (PEM format)
 * @param[out] outputLen Length of the decrypted private key
 * @return Error code
 **/

error_t pemDecryptPrivateKey(const char_t *input, size_t inputLen,
   const char_t *password, char_t *output, size_t *outputLen)
{
#if (PEM_ENCRYPTED_KEY_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   PemHeader header;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(input == NULL || password == NULL || output == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the PrivateKeyInfo structure
   osMemset(&privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

#if (RSA_SUPPORT == ENABLED)
   //RSA private key?
   if(pemDecodeFile(input, inputLen, "RSA PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, inputLen, "RSA PRIVATE KEY", buffer, &n,
            &header, NULL);

         //Check status code
         if(!error)
         {
            //Check whether the PEM file is encrypted
            if(pemCompareString(&header.procType.type, "ENCRYPTED"))
            {
               //Perform decryption
               error = pemDecryptMessage(&header, password, buffer, n,
                  buffer, &n);
            }
         }

         //Check status code
         if(!error)
         {
            //Read RSAPrivateKey structure
            error = pkcs8ParseRsaPrivateKey(buffer, n,
               &privateKeyInfo.rsaPrivateKey);
         }

         //Check status code
         if(!error)
         {
            //Export the RSA private key to PEM format
            error = pemEncodeFile(buffer, n, "RSA PRIVATE KEY", output,
               outputLen);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA private key?
   if(pemDecodeFile(input, inputLen, "DSA PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, inputLen, "DSA PRIVATE KEY", buffer, &n,
            &header, NULL);

         //Check status code
         if(!error)
         {
            //Check whether the PEM file is encrypted
            if(pemCompareString(&header.procType.type, "ENCRYPTED"))
            {
               //Perform decryption
               error = pemDecryptMessage(&header, password, buffer, n,
                  buffer, &n);
            }
         }

         //Check status code
         if(!error)
         {
            //Read DSAPrivateKey structure
            error = pkcs8ParseDsaPrivateKey(buffer, n, &privateKeyInfo.dsaParams,
               &privateKeyInfo.dsaPrivateKey, &privateKeyInfo.dsaPublicKey);
         }

         //Check status code
         if(!error)
         {
            //Export the DSA private key to PEM format
            error = pemEncodeFile(buffer, n, "DSA PRIVATE KEY", output,
               outputLen);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //EC private key?
   if(pemDecodeFile(input, inputLen, "EC PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, inputLen, "EC PRIVATE KEY", buffer, &n,
            &header, NULL);

         //Check status code
         if(!error)
         {
            //Check whether the PEM file is encrypted
            if(pemCompareString(&header.procType.type, "ENCRYPTED"))
            {
               //Perform decryption
               error = pemDecryptMessage(&header, password, buffer, n,
                  buffer, &n);
            }
         }

         //Check status code
         if(!error)
         {
            //Read ECPrivateKey structure
            error = pkcs8ParseEcPrivateKey(buffer, n, &privateKeyInfo.ecParams,
               &privateKeyInfo.ecPrivateKey, &privateKeyInfo.ecPublicKey);
         }

         //Check status code
         if(!error)
         {
            //Export the EC private key to PEM format
            error = pemEncodeFile(buffer, n, "EC PRIVATE KEY", output,
               outputLen);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
#endif
   //PKCS #8 format private key?
   if(pemDecodeFile(input, inputLen, "PRIVATE KEY", NULL, &n,
      NULL, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, inputLen, "PRIVATE KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Export the private key to PEM format
            error = pemEncodeFile(buffer, n, "PRIVATE KEY", output, outputLen);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   //PKCS #8 format encrypted private key?
   else if(pemDecodeFile(input, inputLen, "ENCRYPTED PRIVATE KEY", NULL, &n,
      NULL, NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         uint8_t *data;
         Pkcs8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

         //Decode the content of the PEM container
         error = pemDecodeFile(input, inputLen, "ENCRYPTED PRIVATE KEY", buffer,
            &n, NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the EncryptedPrivateKeyInfo structure (refer to RFC 5208,
            //section 6)
            error = pkcs8ParseEncryptedPrivateKeyInfo(buffer, n,
               &encryptedPrivateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Point to the encrypted data
            data = (uint8_t *) encryptedPrivateKeyInfo.encryptedData.value;
            n = encryptedPrivateKeyInfo.encryptedData.length;

            //Decrypt the private key information
            error = pkcs5Decrypt(&encryptedPrivateKeyInfo.encryptionAlgo,
               password, data, n, data, &n);
         }

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(data, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Export the private key to PEM format
            error = pemEncodeFile(data, n, "PRIVATE KEY", output, outputLen);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid private key
      error = ERROR_END_OF_FILE;
   }

   //Return status code
   return error;
#else
   //Encrypted private keys are not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief PEM message decryption
 * @param[in] header PEM encapsulated header
 * @param[in] password NULL-terminated string containing the password
 * @param[in] ciphertext Pointer to the ciphertext data
 * @param[in] ciphertextLen Length of the ciphertext data, in bytes
 * @param[out] plaintext Pointer to the plaintext data
 * @param[out] plaintextLen Length of the plaintext data, in bytes
 * @return Error code
 **/

error_t pemDecryptMessage(const PemHeader *header, const char_t *password,
   const uint8_t *ciphertext, size_t ciphertextLen, uint8_t *plaintext,
   size_t *plaintextLen)
{
#if (PEM_ENCRYPTED_KEY_SUPPORT == ENABLED)
   error_t error;
   size_t i;
   size_t dkLen;
   size_t psLen;
   size_t passwordLen;
   uint8_t dk[32];
   uint8_t iv[16];
   const CipherAlgo *cipherAlgo;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   CipherContext *cipherContext;
#else
   CipherContext cipherContext[1];
#endif

   //Check parameters
   if(header == NULL || password == NULL || ciphertext == NULL ||
      plaintext == NULL || plaintextLen == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Messages processed according to RFC 1421 will carry the subfield value "4"
   if(!pemCompareString(&header->procType.version, "4"))
      return ERROR_INVALID_VERSION;

   //Retrieve cipher algorithm
   cipherAlgo = pemGetCipherAlgo(&header->dekInfo.algo);
   //Invalid cipher algorithm?
   if(cipherAlgo == NULL)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //Obtain the key length in octets for the derived key
   dkLen = pemGetKeyLength(&header->dekInfo.algo);
   //Invalid key length?
   if(dkLen == 0)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //If the length in octets of the ciphertext C is not a multiple of the block
   //size, output a decryption error and stop
   if((ciphertextLen % cipherAlgo->blockSize) != 0)
      return ERROR_DECRYPTION_FAILED;

   //Extract the IV from the PEM encapsulated header
   error = pemFormatIv(header, iv, cipherAlgo->blockSize);
   //Any error to report?
   if(error)
      return error;

   //Retrieve the length of the password
   passwordLen = osStrlen(password);

   //Apply the key derivation function to produce a derived key DK
   error = pemKdf(password, passwordLen, iv, 8, dk, dkLen);
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
      //Decrypt the ciphertext C with the underlying block cipher in CBC
      //mode under the encryption key K with initialization vector IV to
      //recover an encoded message EM
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
#else
   //Encrypted private keys are not supported
   return ERROR_DECRYPTION_FAILED;
#endif
}


/**
 * @brief Extract the IV from the PEM encapsulated header
 * @param[in] header PEM encapsulated header
 * @param[out] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector, in bytes
 * @return Error code
 **/

error_t pemFormatIv(const PemHeader *header, uint8_t *iv, size_t ivLen)
{
   error_t error;
   size_t i;
   char_t *end;
   char_t buffer[3];

   //Check the length of the IV
   if(header->dekInfo.iv.length == (2 * ivLen))
   {
      //Initialize status code
      error = NO_ERROR;

      //Extract the IV from the PEM encapsulated header
      for(i = 0; i < ivLen && !error; i++)
      {
         //Hexadecimal representation of the current byte
         buffer[0] = header->dekInfo.iv.value[2 * i];
         buffer[1] = header->dekInfo.iv.value[2 * i + 1];
         buffer[2] = '\0';

         //Convert the current byte
         iv[i] = (uint8_t) osStrtoul(buffer, &end, 16);

         //Syntax error?
         if(*end != '\0')
         {
            error = ERROR_INVALID_SYNTAX;
         }
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_SYNTAX;
   }

   //Return status code
   return error;
}


/**
 * @brief Key derivation function
 * @param[in] p Password, an octet string
 * @param[in] pLen Length in octets of password
 * @param[in] s Salt, an octet string
 * @param[in] sLen Length in octets of salt
 * @param[out] dk Derived key
 * @param[in] dkLen Intended length in octets of the derived key
 * @return Error code
 **/

error_t pemKdf(const char_t *p, size_t pLen, const uint8_t *s, size_t sLen,
   uint8_t *dk, size_t dkLen)
{
#if (PEM_ENCRYPTED_KEY_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   size_t n;
   uint8_t t[MD5_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Md5Context *md5Context;
#else
   Md5Context md5Context[1];
#endif

   //Check parameters
   if(p == NULL || s == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the MD5 context
   md5Context = cryptoAllocMem(sizeof(Md5Context));
   //Failed to allocate memory?
   if(md5Context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Apply the hash function to generate the first block
   md5Init(md5Context);
   md5Update(md5Context, p, pLen);
   md5Update(md5Context, s, sLen);
   md5Final(md5Context, t);

   //Save the resulting block
   n = MIN(dkLen, MD5_DIGEST_SIZE);
   osMemcpy(dk, t, n);

   //Point to the next block
   dk += n;
   dkLen -= n;

   //Generate subsequent blocks
   while(dkLen > 0)
   {
      //Apply the hash function to generate a new block
      md5Init(md5Context);
      md5Update(md5Context, t, MD5_DIGEST_SIZE);
      md5Update(md5Context, p, pLen);
      md5Update(md5Context, s, sLen);
      md5Final(md5Context, t);

      //Save the resulting block
      n = MIN(dkLen, MD5_DIGEST_SIZE);
      osMemcpy(dk, t, n);

      //Point to the next block
      dk += n;
      dkLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(md5Context);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //Encrypted private keys are not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Get the cipher algorithm to be used for PEM encryption/decryption
 * @param[in] algo Encryption algorithm
 * @return Cipher algorithm
 **/

const CipherAlgo *pemGetCipherAlgo(const PemString *algo)
{
   const CipherAlgo *cipherAlgo;

#if (PEM_DES_SUPPORT == ENABLED && DES_SUPPORT == ENABLED)
   //DES-CBC algorithm identifier?
   if(pemCompareString(algo, "DES-CBC"))
   {
      cipherAlgo = DES_CIPHER_ALGO;
   }
   else
#endif
#if (PEM_3DES_SUPPORT == ENABLED && DES3_SUPPORT == ENABLED)
   //DES-EDE3-CBC algorithm identifier?
   if(pemCompareString(algo, "DES-EDE3-CBC"))
   {
      cipherAlgo = DES3_CIPHER_ALGO;
   }
   else
#endif
#if (PEM_AES_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
   //AES-128-CBC algorithm identifier?
   if(pemCompareString(algo, "AES-128-CBC"))
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   //AES-192-CBC algorithm identifier?
   else if(pemCompareString(algo, "AES-192-CBC"))
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   //AES-256-CBC algorithm identifier?
   else if(pemCompareString(algo, "AES-256-CBC"))
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   else
#endif
#if (PEM_CAMELLIA_SUPPORT == ENABLED && CAMELLIA_SUPPORT == ENABLED)
   //Camellia-128-CBC algorithm identifier?
   if(pemCompareString(algo, "CAMELLIA-128-CBC"))
   {
      cipherAlgo = CAMELLIA_CIPHER_ALGO;
   }
   //Camellia-192-CBC algorithm identifier?
   else if(pemCompareString(algo, "CAMELLIA-192-CBC"))
   {
      cipherAlgo = CAMELLIA_CIPHER_ALGO;
   }
   //Camellia-256-CBC algorithm identifier?
   else if(pemCompareString(algo, "CAMELLIA-256-CBC"))
   {
      cipherAlgo = CAMELLIA_CIPHER_ALGO;
   }
   else
#endif
#if (PEM_ARIA_SUPPORT == ENABLED && ARIA_SUPPORT == ENABLED)
   //ARIA-128-CBC algorithm identifier?
   if(pemCompareString(algo, "ARIA-128-CBC"))
   {
      cipherAlgo = ARIA_CIPHER_ALGO;
   }
   //ARIA-192-CBC algorithm identifier?
   else if(pemCompareString(algo, "ARIA-192-CBC"))
   {
      cipherAlgo = ARIA_CIPHER_ALGO;
   }
   //ARIA-256-CBC algorithm identifier?
   else if(pemCompareString(algo, "ARIA-256-CBC"))
   {
      cipherAlgo = ARIA_CIPHER_ALGO;
   }
   else
#endif
#if (PEM_SM4_SUPPORT == ENABLED && SM4_SUPPORT == ENABLED)
   //SM4-CBC algorithm identifier?
   if(pemCompareString(algo, "SM4-CBC"))
   {
      cipherAlgo = SM4_CIPHER_ALGO;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      cipherAlgo = NULL;
   }

   //Return the cipher algorithm that matches the specified OID
   return cipherAlgo;
}


/**
 * @brief Get the encryption key length to be used for PEM encryption/decryption
 * @param[in] algo Encryption algorithm
 * @return Encryption key length
 **/

uint_t pemGetKeyLength(const PemString *algo)
{
   uint_t keyLen;

#if (PEM_DES_SUPPORT == ENABLED && DES_SUPPORT == ENABLED)
   //DES-CBC algorithm algorithm?
   if(pemCompareString(algo, "DES-CBC"))
   {
      keyLen = 8;
   }
   else
#endif
#if (PEM_3DES_SUPPORT == ENABLED && DES3_SUPPORT == ENABLED)
   //DES-EDE3-CBC algorithm algorithm?
   if(pemCompareString(algo, "DES-EDE3-CBC"))
   {
      keyLen = 24;
   }
   else
#endif
#if (PEM_AES_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
   //AES-128-CBC algorithm algorithm?
   if(pemCompareString(algo, "AES-128-CBC"))
   {
      keyLen = 16;
   }
   //AES-192-CBC algorithm algorithm?
   else if(pemCompareString(algo, "AES-192-CBC"))
   {
      keyLen = 24;
   }
   //AES-256-CBC algorithm algorithm?
   else if(pemCompareString(algo, "AES-256-CBC"))
   {
      keyLen = 32;
   }
   else
#endif
#if (PEM_CAMELLIA_SUPPORT == ENABLED && CAMELLIA_SUPPORT == ENABLED)
   //Camellia-128-CBC algorithm identifier?
   if(pemCompareString(algo, "CAMELLIA-128-CBC"))
   {
      keyLen = 16;
   }
   //Camellia-192-CBC algorithm identifier?
   else if(pemCompareString(algo, "CAMELLIA-192-CBC"))
   {
      keyLen = 24;
   }
   //Camellia-256-CBC algorithm identifier?
   else if(pemCompareString(algo, "CAMELLIA-256-CBC"))
   {
      keyLen = 32;
   }
   else
#endif
#if (PEM_ARIA_SUPPORT == ENABLED && ARIA_SUPPORT == ENABLED)
   //ARIA-128-CBC algorithm identifier?
   if(pemCompareString(algo, "ARIA-128-CBC"))
   {
      keyLen = 16;
   }
   //ARIA-192-CBC algorithm identifier?
   else if(pemCompareString(algo, "ARIA-192-CBC"))
   {
      keyLen = 24;
   }
   //ARIA-256-CBC algorithm identifier?
   else if(pemCompareString(algo, "ARIA-256-CBC"))
   {
      keyLen = 32;
   }
   else
#endif
#if (PEM_SM4_SUPPORT == ENABLED && SM4_SUPPORT == ENABLED)
   //SM4-CBC algorithm identifier?
   if(pemCompareString(algo, "SM4-CBC"))
   {
      keyLen = 16;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      keyLen = 0;
   }

   //Return the encryption key length that matches the specified OID
   return keyLen;
}

#endif
