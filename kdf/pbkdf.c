/**
 * @file pbkdf.c
 * @brief PBKDF (Password-Based Key Derivation Function)
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "kdf/pbkdf.h"
#include "mac/mac_algorithms.h"

//Check crypto library configuration
#if (PBKDF_SUPPORT == ENABLED)

//PBKDF2 OID (1.2.840.113549.1.5.12)
const uint8_t PBKDF2_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C};


/**
 * @brief PBKDF1 key derivation function
 *
 * PBKDF1 applies a hash function, which shall be MD2, MD5 or SHA-1, to derive
 * keys. The length of the derived key is bounded by the length of the hash
 * function output, which is 16 octets for MD2 and MD5 and 20 octets for SHA-1
 *
 * @param[in] hashAlgo Underlying hash function (MD2, MD5 or SHA-1)
 * @param[in] p Password, an octet string
 * @param[in] pLen Length in octets of password
 * @param[in] s Salt, an octet string
 * @param[in] sLen Length in octets of salt
 * @param[in] c Iteration count
 * @param[out] dk Derived key
 * @param[in] dkLen Intended length in octets of the derived key
 * @return Error code
 **/

error_t pbkdf1(const HashAlgo *hashAlgo, const uint8_t *p, size_t pLen,
   const uint8_t *s, size_t sLen, uint_t c, uint8_t *dk, size_t dkLen)
{
   uint_t i;
   uint8_t t[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || p == NULL || s == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The iteration count must be a positive integer
   if(c < 1)
      return ERROR_INVALID_PARAMETER;

   //Check the intended length of the derived key
   if(dkLen > hashAlgo->digestSize)
      return ERROR_INVALID_LENGTH;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hashAlgo->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Apply the hash function to the concatenation of P and S
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, p, pLen);
   hashAlgo->update(hashContext, s, sLen);
   hashAlgo->final(hashContext, t);

   //Iterate as many times as required
   for(i = 1; i < c; i++)
   {
      //Apply the hash function to T(i - 1)
      hashAlgo->init(hashContext);
      hashAlgo->update(hashContext, t, hashAlgo->digestSize);
      hashAlgo->final(hashContext, t);
   }

   //Output the derived key DK
   osMemcpy(dk, t, dkLen);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hashContext);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief PBKDF2 key derivation function
 *
 * PBKDF2 applies a pseudorandom function to derive keys. The length of the
 * derived key is essentially unbounded
 *
 * @param[in] type Pseudorandom function (HMAC or AES-CMAC-PRF-128)
 * @param[in] hashAlgo Underlying hash function (only for HMAC PRF)
 * @param[in] p Password, an octet string
 * @param[in] pLen Length in octets of password
 * @param[in] s Salt, an octet string
 * @param[in] sLen Length in octets of salt
 * @param[in] c Iteration count
 * @param[out] dk Derived key
 * @param[in] dkLen Intended length in octets of the derived key
 * @return Error code
 **/

error_t pbkdf2(Pbkdf2Type type, const HashAlgo *hashAlgo, const uint8_t *p,
   size_t pLen, const uint8_t *s, size_t sLen, uint_t c, uint8_t *dk,
   size_t dkLen)
{
   error_t error;

   //HMAC or AES-CMAC-PRF-128 pseudorandom function?
   if(type == PBKDF2_TYPE_HMAC)
   {
      error = pbkdf2Hmac(hashAlgo, p, pLen, s, sLen, c, dk, dkLen);
   }
   else if(type == PBKDF2_TYPE_AES_CMAC_PRF_128)
   {
      error = pbkdf2AesCmacPrf128(p, pLen, s, sLen, c, dk, dkLen);
   }
   else
   {
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief PBKDF2 key derivation function (with HMAC)
 * @param[in] hashAlgo Underlying hash function
 * @param[in] p Password, an octet string
 * @param[in] pLen Length in octets of password
 * @param[in] s Salt, an octet string
 * @param[in] sLen Length in octets of salt
 * @param[in] c Iteration count
 * @param[out] dk Derived key
 * @param[in] dkLen Intended length in octets of the derived key
 * @return Error code
 **/

error_t pbkdf2Hmac(const HashAlgo *hashAlgo, const uint8_t *p, size_t pLen,
   const uint8_t *s, size_t sLen, uint_t c, uint8_t *dk, size_t dkLen)
{
#if (HMAC_SUPPORT == ENABLED)
   uint_t i;
   uint_t j;
   uint_t k;
   uint8_t a[4];
   uint8_t t[MAX_HASH_DIGEST_SIZE];
   uint8_t u[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || p == NULL || s == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The iteration count must be a positive integer
   if(c < 1)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //For each block of the derived key apply the function F
   for(i = 1; dkLen > 0; i++)
   {
      //Calculate the 4-octet encoding of the integer i (MSB first)
      STORE32BE(i, a);

      //Compute U1 = PRF(P, S || INT(i))
      hmacInit(hmacContext, hashAlgo, p, pLen);
      hmacUpdate(hmacContext, s, sLen);
      hmacUpdate(hmacContext, a, 4);
      hmacFinal(hmacContext, u);

      //Save the resulting HMAC value
      osMemcpy(t, u, hashAlgo->digestSize);

      //Iterate as many times as required
      for(j = 1; j < c; j++)
      {
         //Compute U(j) = PRF(P, U(j-1))
         hmacInit(hmacContext, hashAlgo, p, pLen);
         hmacUpdate(hmacContext, u, hashAlgo->digestSize);
         hmacFinal(hmacContext, u);

         //Compute T = U(1) xor U(2) xor ... xor U(c)
         for(k = 0; k < hashAlgo->digestSize; k++)
         {
            t[k] ^= u[k];
         }
      }

      //Number of octets in the current block
      k = MIN(dkLen, hashAlgo->digestSize);
      //Save the resulting block
      osMemcpy(dk, t, k);

      //Point to the next block
      dk += k;
      dkLen -= k;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //HMAC pseudorandom function is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief PBKDF2 key derivation function (with AES-CMAC-PRF-128)
 * @param[in] p Password, an octet string
 * @param[in] pLen Length in octets of password
 * @param[in] s Salt, an octet string
 * @param[in] sLen Length in octets of salt
 * @param[in] c Iteration count
 * @param[out] dk Derived key
 * @param[in] dkLen Intended length in octets of the derived key
 * @return Error code
 **/

error_t pbkdf2AesCmacPrf128(const uint8_t *p, size_t pLen, const uint8_t *s,
   size_t sLen, uint_t c, uint8_t *dk, size_t dkLen)
{
#if (CMAC_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
   uint_t i;
   uint_t j;
   uint_t n;
   uint8_t a[4];
   uint8_t k[16];
   uint8_t t[16];
   uint8_t u[16];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   CmacContext *cmacContext;
#else
   CmacContext cmacContext[1];
#endif

   //Check parameters
   if(p == NULL || s == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The iteration count must be a positive integer
   if(c < 1)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the CMAC context
   cmacContext = cryptoAllocMem(sizeof(CmacContext));
   //Failed to allocate memory?
   if(cmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Derive the 128-bit key K from the variable-length key VK
   if(pLen == 16)
   {
      //If the key VK is exactly 128 bits, then we use it as-is
      osMemcpy(k, p, pLen);
   }
   else
   {
      //If the key VK is longer or shorter than 128 bits, then we derive the
      //key K by applying the AES-CMAC algorithm using the 128-bit all-zero
      //string as the key and VK as the input message (refer to RFC 4615,
      //section 3)
      osMemset(k, 0, 16);

      //Compute K = AES-CMAC(0^128, VK, VKlen)
      cmacInit(cmacContext, AES_CIPHER_ALGO, k, 16);
      cmacUpdate(cmacContext, p, pLen);
      cmacFinal(cmacContext, k, 16);
   }

   //For each block of the derived key apply the function F
   for(i = 1; dkLen > 0; i++)
   {
      //Calculate the 4-octet encoding of the integer i (MSB first)
      STORE32BE(i, a);

      //Compute U1 = PRF(P, S || INT(i))
      cmacInit(cmacContext, AES_CIPHER_ALGO, k, 16);
      cmacUpdate(cmacContext, s, sLen);
      cmacUpdate(cmacContext, a, 4);
      cmacFinal(cmacContext, u, 16);

      //Save the resulting CMAC value
      osMemcpy(t, u, 16);

      //Iterate as many times as required
      for(j = 1; j < c; j++)
      {
         //Compute U(j) = PRF(P, U(j-1))
         cmacInit(cmacContext, AES_CIPHER_ALGO, k, 16);
         cmacUpdate(cmacContext, u, 16);
         cmacFinal(cmacContext, u, 16);

         //Compute T = U(1) xor U(2) xor ... xor U(c)
         for(n = 0; n < 16; n++)
         {
            t[n] ^= u[n];
         }
      }

      //Number of octets in the current block
      n = MIN(dkLen, 16);
      //Save the resulting block
      osMemcpy(dk, t, n);

      //Point to the next block
      dk += n;
      dkLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(cmacContext);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //AES-CMAC-PRF-128 pseudorandom function is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
