/**
 * @file one_step_kdf.c
 * @brief One-Step KDF
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @section Description
 *
 * One-Step KDF is a key derivation function defined by NIST SP 800-56C
 * revision 1, section 4
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "kdf/one_step_kdf.h"
#include "mac/mac_algorithms.h"

//Check crypto library configuration
#if (ONE_STEP_KDF_SUPPORT == ENABLED)

//Default salt value for HMAC and KMAC auxiliary functions
static const uint8_t defaultSalt[164] =
{
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00
};


/**
 * @brief One-Step KDF function
 * @param[in] type Auxiliary function H (hash, HMAC or KMAC)
 * @param[in] hashAlgo Underlying hash function (for hash and HMAC-based
 *   auxiliary functions only)
 * @param[in] z Shared secret Z
 * @param[in] zLen Length of the shared secret Z, in bytes
 * @param[in] salt Salt value (for HMAC and KMAC-based auxiliary functions only)
 * @param[in] saltLen Length of the salt value, in bytes
 * @param[in] otherInfo Context-specific information (optional parameter)
 * @param[in] otherInfoLen Length of the context-specific information, in bytes
 * @param[out] dk Derived keying material
 * @param[in] dkLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t oneStepKdf(OneStepKdfType type, const HashAlgo *hashAlgo,
   const uint8_t *z, size_t zLen, const uint8_t *salt, size_t saltLen,
   const uint8_t *otherInfo, size_t otherInfoLen, uint8_t *dk, size_t dkLen)
{
   error_t error;

   //The One-Step KDF uses an auxiliary function H, which can be either an
   //approved hash function, an HMAC with an approved hash function or a KMAC
   //variant
   if(type == ONE_STEP_KDF_TYPE_HASH)
   {
      error = oneStepKdfHash(hashAlgo, z, zLen, otherInfo, otherInfoLen,
         dk, dkLen);
   }
   else if(type == ONE_STEP_KDF_TYPE_HMAC)
   {
      error = oneStepKdfHmac(hashAlgo, z, zLen, salt, saltLen, otherInfo,
         otherInfoLen, dk, dkLen);
   }
   else if(type == ONE_STEP_KDF_TYPE_KMAC128)
   {
      error = oneStepKdfKmac(128, dkLen, z, zLen, salt, saltLen, otherInfo,
         otherInfoLen, dk, dkLen);
   }
   else if(type == ONE_STEP_KDF_TYPE_KMAC256)
   {
      error = oneStepKdfKmac(256, dkLen, z, zLen, salt, saltLen, otherInfo,
         otherInfoLen, dk, dkLen);
   }
   else
   {
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief One-Step KDF function (with hash-based auxiliary function)
 * @param[in] hashAlgo Underlying hash function
 * @param[in] z Shared secret Z
 * @param[in] zLen Length of the shared secret Z, in bytes
 * @param[in] otherInfo Context-specific information (optional parameter)
 * @param[in] otherInfoLen Length of the context-specific information, in bytes
 * @param[out] dk Derived keying material
 * @param[in] dkLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t oneStepKdfHash(const HashAlgo *hashAlgo, const uint8_t *z,
   size_t zLen, const uint8_t *otherInfo, size_t otherInfoLen, uint8_t *dk,
   size_t dkLen)
{
   size_t n;
   uint32_t i;
   uint8_t counter[4];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || z == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The OtherInfo parameter is optional
   if(otherInfo == NULL && otherInfoLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The length of the derived keying material (L) must be a positive integer
   if(dkLen == 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hashAlgo->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Derive the keying material
   for(i = 1; dkLen > 0; i++)
   {
      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Compute H(counter || Z || OtherInfo)
      hashAlgo->init(hashContext);
      hashAlgo->update(hashContext, counter, sizeof(uint32_t));
      hashAlgo->update(hashContext, z, zLen);
      hashAlgo->update(hashContext, otherInfo, otherInfoLen);
      hashAlgo->final(hashContext, digest);

      //Number of octets in the current block
      n = MIN(dkLen, hashAlgo->digestSize);
      //Save the resulting block
      osMemcpy(dk, digest, n);

      //Point to the next block
      dk += n;
      dkLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hashContext);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief One-Step KDF function (with HMAC-based auxiliary function)
 * @param[in] hashAlgo Underlying hash function
 * @param[in] z Shared secret Z
 * @param[in] zLen Length of the shared secret Z, in bytes
 * @param[in] salt Salt value
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] otherInfo Context-specific information (optional parameter)
 * @param[in] otherInfoLen Length of the context-specific information, in bytes
 * @param[out] dk Derived keying material
 * @param[in] dkLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t oneStepKdfHmac(const HashAlgo *hashAlgo, const uint8_t *z,
   size_t zLen, const uint8_t *salt, size_t saltLen, const uint8_t *otherInfo,
   size_t otherInfoLen, uint8_t *dk, size_t dkLen)
{
#if (HMAC_SUPPORT == ENABLED)
   size_t n;
   uint32_t i;
   uint8_t counter[4];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || z == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The salt parameter is optional
   if(salt == NULL && saltLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The OtherInfo parameter is optional
   if(otherInfo == NULL && otherInfoLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The length of the derived keying material (L) must be a positive integer
   if(dkLen == 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //If the salt value is omitted, then the default salt shall be used
   if(salt == NULL)
   {
      //The default salt shall be an all-zero byte string whose bit length
      //equals that specified as the bit length of an input block for the hash
      //function
      salt = defaultSalt;
      saltLen = hashAlgo->blockSize;
   }

   //Derive the keying material
   for(i = 1; dkLen > 0; i++)
   {
      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Compute H(counter || Z || OtherInfo)
      hmacInit(hmacContext, hashAlgo, salt, saltLen);
      hmacUpdate(hmacContext, counter, sizeof(uint32_t));
      hmacUpdate(hmacContext, z, zLen);
      hmacUpdate(hmacContext, otherInfo, otherInfoLen);
      hmacFinal(hmacContext, digest);

      //Number of octets in the current block
      n = MIN(dkLen, hashAlgo->digestSize);
      //Save the resulting block
      osMemcpy(dk, digest, n);

      //Point to the next block
      dk += n;
      dkLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //HMAC-based auxiliary function is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief One-Step KDF function (with KMAC-based auxiliary function)
 * @param[in] strength Number of bits of security (128 for KMAC128 and
 *   256 for KMAC256)
 * @param[in] hLen Length of of the auxiliary function output, in bytes
 * @param[in] z Shared secret Z
 * @param[in] zLen Length of the shared secret Z, in bytes
 * @param[in] salt Salt value
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] otherInfo Context-specific information (optional parameter)
 * @param[in] otherInfoLen Length of the context-specific information, in bytes
 * @param[out] dk Derived keying material
 * @param[in] dkLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t oneStepKdfKmac(uint_t strength, size_t hLen, const uint8_t *z,
   size_t zLen, const uint8_t *salt, size_t saltLen, const uint8_t *otherInfo,
   size_t otherInfoLen, uint8_t *dk, size_t dkLen)
{
#if (KMAC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint32_t i;
   uint8_t counter[4];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   KmacContext *kmacContext;
#else
   KmacContext kmacContext[1];
#endif

   //The KMAC variant must be either KMAC128 or KMAC256
   if(strength != 128 && strength != 256)
      return ERROR_INVALID_PARAMETER;

   //H_outputBits shall either be set equal to the length (in bits) of the
   //secret keying material to be derived (L) or selected from the set {160,
   //224, 256, 384, 512}
   if(hLen != 20 && hLen != 28 && hLen != 32 && hLen != 48 && hLen != 64 &&
      hLen != dkLen)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Check parameters
   if(z == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The salt parameter is optional
   if(salt == NULL && saltLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The OtherInfo parameter is optional
   if(otherInfo == NULL && otherInfoLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The length of the derived keying material (L) must be a positive integer
   if(dkLen == 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the KMAC context
   kmacContext = cryptoAllocMem(sizeof(KmacContext));
   //Failed to allocate memory?
   if(kmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //If the salt value is omitted, then the default salt shall be used
   if(salt == NULL)
   {
      //Point to the default salt
      salt = defaultSalt;

      //The default salt shall be an all-zero string of 164 bytes for KMAC128,
      //and 132 bytes for KMAC256
      if(strength == 128)
      {
         saltLen = ONE_STEP_KDF_KMAC128_DEFAULT_SALT_LEN;
      }
      else
      {
         saltLen = ONE_STEP_KDF_KMAC256_DEFAULT_SALT_LEN;
      }
   }

   //Initialize status code
   error = NO_ERROR;

   //Derive the keying material
   for(i = 1; dkLen > 0 && !error; i++)
   {
      //Number of octets in the current block
      n = MIN(dkLen, hLen);

      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Initialize KMAC calculation
      error = kmacInit(kmacContext, strength, salt, saltLen, "KDF", 3);

      //Check status code
      if(!error)
      {
         //Compute H(counter || Z || OtherInfo)
         kmacUpdate(kmacContext, counter, sizeof(uint32_t));
         kmacUpdate(kmacContext, z, zLen);
         kmacUpdate(kmacContext, otherInfo, otherInfoLen);

         //Finalize KMAC calculation
         kmacFinal(kmacContext, dk, n);
      }

      //Point to the next block
      dk += n;
      dkLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(kmacContext);
#endif

   //Return status code
   return error;
#else
   //KMAC-based auxiliary function is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
