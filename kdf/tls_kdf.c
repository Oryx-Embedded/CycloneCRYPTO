/**
 * @file tls_kdf.c
 * @brief TLS key derivation functions
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
#include "kdf/tls_kdf.h"
#include "kdf/hkdf.h"
#include "mac/hmac.h"

//Check crypto library configuration
#if (TLS_KDF_SUPPORT == ENABLED)


/**
 * @brief Pseudorandom function (TLS 1.0 and 1.1)
 *
 * The pseudorandom function (PRF) takes as input a secret, a seed, and
 * an identifying label and produces an output of arbitrary length. This
 * function is used to expand secrets into blocks of data for the purpose
 * of key generation
 *
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] seed Pointer to the seed
 * @param[in] seedLen Length of the seed
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t tlsPrf(const uint8_t *secret, size_t secretLen, const char_t *label,
   const uint8_t *seed, size_t seedLen, uint8_t *output, size_t outputLen)
{
#if (MD5_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   uint_t i;
   uint_t j;
   size_t labelLen;
   size_t sLen;
   const uint8_t *s1;
   const uint8_t *s2;
   uint8_t a[SHA1_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(secret == NULL || label == NULL || seed == NULL || output == NULL)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Retrieve the length of the label
   labelLen = osStrlen(label);

   //The secret is partitioned into two halves S1 and S2
   //with the possibility of one shared byte
   sLen = (secretLen + 1) / 2;
   //S1 is taken from the first half of the secret
   s1 = secret;
   //S2 is taken from the second half
   s2 = secret + secretLen - sLen;

   //First compute A(1) = HMAC_MD5(S1, label + seed)
   hmacInit(hmacContext, MD5_HASH_ALGO, s1, sLen);
   hmacUpdate(hmacContext, label, labelLen);
   hmacUpdate(hmacContext, seed, seedLen);
   hmacFinal(hmacContext, a);

   //Apply the data expansion function P_MD5
   for(i = 0; i < outputLen; )
   {
      //Compute HMAC_MD5(S1, A(i) + label + seed)
      hmacInit(hmacContext, MD5_HASH_ALGO, s1, sLen);
      hmacUpdate(hmacContext, a, MD5_DIGEST_SIZE);
      hmacUpdate(hmacContext, label, labelLen);
      hmacUpdate(hmacContext, seed, seedLen);
      hmacFinal(hmacContext, NULL);

      //Copy the resulting digest
      for(j = 0; i < outputLen && j < MD5_DIGEST_SIZE; i++, j++)
      {
         output[i] = hmacContext->digest[j];
      }

      //Compute A(i + 1) = HMAC_MD5(S1, A(i))
      hmacInit(hmacContext, MD5_HASH_ALGO, s1, sLen);
      hmacUpdate(hmacContext, a, MD5_DIGEST_SIZE);
      hmacFinal(hmacContext, a);
   }

   //First compute A(1) = HMAC_SHA1(S2, label + seed)
   hmacInit(hmacContext, SHA1_HASH_ALGO, s2, sLen);
   hmacUpdate(hmacContext, label, labelLen);
   hmacUpdate(hmacContext, seed, seedLen);
   hmacFinal(hmacContext, a);

   //Apply the data expansion function P_SHA1
   for(i = 0; i < outputLen; )
   {
      //Compute HMAC_SHA1(S2, A(i) + label + seed)
      hmacInit(hmacContext, SHA1_HASH_ALGO, s2, sLen);
      hmacUpdate(hmacContext, a, SHA1_DIGEST_SIZE);
      hmacUpdate(hmacContext, label, labelLen);
      hmacUpdate(hmacContext, seed, seedLen);
      hmacFinal(hmacContext, NULL);

      //Copy the resulting digest
      for(j = 0; i < outputLen && j < SHA1_DIGEST_SIZE; i++, j++)
      {
         output[i] ^= hmacContext->digest[j];
      }

      //Compute A(i + 1) = HMAC_SHA1(S2, A(i))
      hmacInit(hmacContext, SHA1_HASH_ALGO, s2, sLen);
      hmacUpdate(hmacContext, a, SHA1_DIGEST_SIZE);
      hmacFinal(hmacContext, a);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Pseudorandom function (TLS 1.2)
 *
 * The pseudorandom function (PRF) takes as input a secret, a seed, and
 * an identifying label and produces an output of arbitrary length. This
 * function is used to expand secrets into blocks of data for the purpose
 * of key generation
 *
 * @param[in] hashAlgo Hash function used to compute PRF
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] seed Pointer to the seed
 * @param[in] seedLen Length of the seed
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t tls12Prf(const HashAlgo *hashAlgo, const uint8_t *secret,
   size_t secretLen, const char_t *label, const uint8_t *seed, size_t seedLen,
   uint8_t *output, size_t outputLen)
{
   size_t n;
   size_t labelLen;
   uint8_t a[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || secret == NULL || label == NULL || seed == NULL ||
      output == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Retrieve the length of the label
   labelLen = osStrlen(label);

   //First compute A(1) = HMAC_hash(secret, label + seed)
   hmacInit(hmacContext, hashAlgo, secret, secretLen);
   hmacUpdate(hmacContext, label, labelLen);
   hmacUpdate(hmacContext, seed, seedLen);
   hmacFinal(hmacContext, a);

   //Apply the data expansion function P_hash
   while(outputLen > 0)
   {
      //Compute HMAC_hash(secret, A(i) + label + seed)
      hmacInit(hmacContext, hashAlgo, secret, secretLen);
      hmacUpdate(hmacContext, a, hashAlgo->digestSize);
      hmacUpdate(hmacContext, label, labelLen);
      hmacUpdate(hmacContext, seed, seedLen);
      hmacFinal(hmacContext, NULL);

      //Calculate the number of bytes to copy
      n = MIN(outputLen, hashAlgo->digestSize);
      //Copy the resulting digest
      osMemcpy(output, hmacContext->digest, n);

      //Compute A(i + 1) = HMAC_hash(secret, A(i))
      hmacInit(hmacContext, hashAlgo, secret, secretLen);
      hmacUpdate(hmacContext, a, hashAlgo->digestSize);
      hmacFinal(hmacContext, a);

      //Advance data pointer
      output += n;
      //Decrement byte counter
      outputLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief HKDF-Expand-Label function (TLS 1.3)
 * @param[in] hashAlgo Hash function used by HKDF
 * @param[in] secret Pointer to the secret
 * @param[in] secretLen Length of the secret
 * @param[in] prefix Label prefix ("tls13 " for TLS, "dtls13" for DTLS)
 * @param[in] label Identifying label (NULL-terminated string)
 * @param[in] context Pointer to the upper-layer context
 * @param[in] contextLen Length of the upper-layer context
 * @param[out] output Pointer to the output
 * @param[in] outputLen Desired output length
 * @return Error code
 **/

error_t hkdfExpandLabel(const HashAlgo *hashAlgo, const uint8_t *secret,
   size_t secretLen, const char_t *prefix, const char_t *label,
   const uint8_t *context, size_t contextLen, uint8_t *output,
   size_t outputLen)
{
#if (HKDF_SUPPORT == ENABLED)
   error_t error;
   size_t prefixLen;
   size_t labelLen;
   uint8_t temp[4];
   DataFrag hkdfLabelFrags[6];

   //Check parameters
   if(prefix == NULL || label == NULL)
      return ERROR_INVALID_PARAMETER;

   if(context == NULL && contextLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the prefix
   prefixLen = osStrlen(prefix);
   //Retrieve the length of the label
   labelLen = osStrlen(label);

   //Check the length of the label
   if((prefixLen + labelLen) < 7 || (prefixLen + labelLen) > 255)
      return ERROR_INVALID_LENGTH;

   //Check the length of the context
   if(contextLen > 255)
      return ERROR_INVALID_LENGTH;

   //Check the length of the output
   if(outputLen > 65535)
      return ERROR_INVALID_LENGTH;

   //The length field is represented as a uint16
   temp[0] = MSB(outputLen);
   temp[1] = LSB(outputLen);
   //The label length is represented as a uint8
   temp[2] = (uint8_t) (prefixLen + labelLen);
   //The context length is represented as a uint8
   temp[3] = (uint8_t) contextLen;

   //Format HkdfLabel structure
   hkdfLabelFrags[0].buffer = &temp[0];
   hkdfLabelFrags[0].length = sizeof(uint16_t);
   hkdfLabelFrags[1].buffer = &temp[2];
   hkdfLabelFrags[1].length = sizeof(uint8_t);
   hkdfLabelFrags[2].buffer = prefix;
   hkdfLabelFrags[2].length = prefixLen;
   hkdfLabelFrags[3].buffer = label;
   hkdfLabelFrags[3].length = labelLen;
   hkdfLabelFrags[4].buffer = &temp[3];
   hkdfLabelFrags[4].length = sizeof(uint8_t);
   hkdfLabelFrags[5].buffer = context;
   hkdfLabelFrags[5].length = contextLen;

   //Compute HKDF-Expand(Secret, HkdfLabel, Length)
   error = hkdfExpandEx(hashAlgo, secret, secretLen, hkdfLabelFrags,
      arraysize(hkdfLabelFrags), output, outputLen);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
