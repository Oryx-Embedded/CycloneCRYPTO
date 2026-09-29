/**
 * @file kbkdf.c
 * @brief SP 800-108 key derivation function
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
 * KBKDF is a key derivation function defined by NIST SP 800-108 revision 1,
 * section 4
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "kdf/kbkdf.h"
#include "mac/mac_algorithms.h"

//Check crypto library configuration
#if (KBKDF_SUPPORT == ENABLED)


/**
 * @brief KBKDF key derivation function (counter mode with HMAC)
 * @param[in] hashAlgo Underlying hash function
 * @param[in] r Length of the binary encoding of the counter, in bits
 * @param[in] ki Key-derivation key KI
 * @param[in] kiLen Length of the key-derivation key, in bytes
 * @param[in] fixedData Fixed input data
 * @param[in] fixedDataLen Length of the fixed input data, in bytes
 * @param[out] ko Derived keying material
 * @param[in] koLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t kbkdfCounterHmac(const HashAlgo *hashAlgo, uint_t r, const uint8_t *ki,
   size_t kiLen, const uint8_t *fixedData, size_t fixedDataLen, uint8_t *ko,
   size_t koLen)

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
   if(hashAlgo == NULL || ki == NULL || ko == NULL)
      return ERROR_INVALID_PARAMETER;

   //The fixed input data is optional
   if(fixedData == NULL && fixedDataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The implementation only supports 8, 16, 24, and 32-bit counters
   if(r != 8 && r != 16 && r != 24 && r != 32)
      return ERROR_INVALID_PARAMETER;

   //Determine how many blocks of keying material are needed
   n = (koLen + hashAlgo->digestSize - 1) / hashAlgo->digestSize;

   //The number of blocks must not exceed the range of the counter
   if(r < 32 && n >= (1U << r))
      return ERROR_INVALID_PARAMETER;

   //Determine the length, in bytes, of the binary encoding of the counter
   r /= 8;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Derive the keying material
   for(i = 1; koLen > 0; i++)
   {
      //Number of octets in the current block
      n = MIN(koLen, hashAlgo->digestSize);

      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Compute K(i) = PRF(KI, [i] || FixedInput)
      hmacInit(hmacContext, hashAlgo, ki, kiLen);
      hmacUpdate(hmacContext, counter + 4 - r, r);
      hmacUpdate(hmacContext, fixedData, fixedDataLen);
      hmacFinal(hmacContext, digest);

      //Save the resulting block
      osMemcpy(ko, digest, n);

      //Point to the next block
      ko += n;
      koLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //HMAC PRF is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief KBKDF key derivation function (counter mode with CMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm
 * @param[in] r Length of the binary encoding of the counter, in bits
 * @param[in] ki Key-derivation key KI
 * @param[in] kiLen Length of the key-derivation key, in bytes
 * @param[in] fixedData Fixed input data
 * @param[in] fixedDataLen Length of the fixed input data, in bytes
 * @param[out] ko Derived keying material
 * @param[in] koLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t kbkdfCounterCmac(const CipherAlgo *cipherAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen)
{
#if (CMAC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint32_t i;
   uint8_t counter[4];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   CmacContext *cmacContext;
#else
   CmacContext cmacContext[1];
#endif

   //Check parameters
   if(cipherAlgo == NULL || ki == NULL || ko == NULL)
      return ERROR_INVALID_PARAMETER;

   //The fixed input data is optional
   if(fixedData == NULL && fixedDataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The implementation only supports 8, 16, 24, and 32-bit counters
   if(r != 8 && r != 16 && r != 24 && r != 32)
      return ERROR_INVALID_PARAMETER;

   //Determine how many blocks of keying material are needed
   n = (koLen + cipherAlgo->blockSize - 1) / cipherAlgo->blockSize;

   //The number of blocks must not exceed the range of the counter
   if(r < 32 && n >= (1U << r))
      return ERROR_INVALID_PARAMETER;

   //Determine the length, in bytes, of the binary encoding of the counter
   r /= 8;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the CMAC context
   cmacContext = cryptoAllocMem(sizeof(CmacContext));
   //Failed to allocate memory?
   if(cmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize status code
   error = NO_ERROR;

   //Derive the keying material
   for(i = 1; koLen > 0 && !error; i++)
   {
      //Number of octets in the current block
      n = MIN(koLen, cipherAlgo->blockSize);

      //Initialize CMAC calculation
      error = cmacInit(cmacContext, cipherAlgo, ki, kiLen);

      //Check status code
      if(!error)
      {
         //Encode the counter as a 32-bit big-endian string
         STORE32BE(i, counter);

         //Compute K(i) = PRF(KI, [i] || FixedInput)
         cmacUpdate(cmacContext, counter + 4 - r, r);
         cmacUpdate(cmacContext, fixedData, fixedDataLen);

         //Finalize CMAC calculation
         error = cmacFinal(cmacContext, ko, n);
      }

      //Point to the next block
      ko += n;
      koLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(cmacContext);
#endif

   //Return status code
   return error;
#else
   //CMAC PRF is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief KBKDF key derivation function (feedback mode with HMAC)
 * @param[in] hashAlgo Underlying hash function
 * @param[in] r Length of the binary encoding of the counter, in bits
 * @param[in] ki Key-derivation key KI
 * @param[in] kiLen Length of the key-derivation key, in bytes
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector, in bytes
 * @param[in] fixedData Fixed input data
 * @param[in] fixedDataLen Length of the fixed input data, in bytes
 * @param[out] ko Derived keying material
 * @param[in] koLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t kbkdfFeedbackHmac(const HashAlgo *hashAlgo, uint_t r, const uint8_t *ki,
   size_t kiLen, const uint8_t *iv, size_t ivLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen)
{
#if (HMAC_SUPPORT == ENABLED)
   size_t n;
   uint32_t i;
   size_t prevLen;
   const uint8_t *prev;
   uint8_t counter[4];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || ki == NULL || ko == NULL)
      return ERROR_INVALID_PARAMETER;

   //The initialization vector is optional
   if(iv == NULL && ivLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The fixed input data is optional
   if(fixedData == NULL && fixedDataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The implementation only supports 8, 16, 24, and 32-bit counters
   if(r != 0 && r != 8 && r != 16 && r != 24 && r != 32)
      return ERROR_INVALID_PARAMETER;

   //Determine the length, in bytes, of the binary encoding of the counter
   r /= 8;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //K(0) is the initialization vector
   prev = iv;
   prevLen = ivLen;

   //Derive the keying material
   for(i = 1; koLen > 0; i++)
   {
      //Number of octets in the current block
      n = MIN(koLen, hashAlgo->digestSize);

      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Compute K(i) = PRF(KI, K(i-1) || [i] || FixedInput)
      hmacInit(hmacContext, hashAlgo, ki, kiLen);
      hmacUpdate(hmacContext, prev, prevLen);
      hmacUpdate(hmacContext, counter + 4 - r, r);
      hmacUpdate(hmacContext, fixedData, fixedDataLen);
      hmacFinal(hmacContext, digest);

      //Save the resulting block
      osMemcpy(ko, digest, n);

      //K(i) becomes the feedback value for the next iteration
      prev = digest;
      prevLen = hashAlgo->digestSize;

      //Point to the next block
      ko += n;
      koLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //HMAC PRF is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief KBKDF key derivation function (feedback mode with CMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm
 * @param[in] r Length of the binary encoding of the counter, in bits
 * @param[in] ki Key-derivation key KI
 * @param[in] kiLen Length of the key-derivation key, in bytes
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector, in bytes
 * @param[in] fixedData Fixed input data
 * @param[in] fixedDataLen Length of the fixed input data, in bytes
 * @param[out] ko Derived keying material
 * @param[in] koLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t kbkdfFeedbackCmac(const CipherAlgo *cipherAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *iv, size_t ivLen,
   const uint8_t *fixedData, size_t fixedDataLen, uint8_t *ko, size_t koLen)
{
#if (CMAC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint32_t i;
   size_t prevLen;
   const uint8_t *prev;
   uint8_t counter[4];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   CmacContext *cmacContext;
#else
   CmacContext cmacContext[1];
#endif

   //Check parameters
   if(cipherAlgo == NULL || ki == NULL || ko == NULL)
      return ERROR_INVALID_PARAMETER;

   //The initialization vector is optional
   if(iv == NULL && ivLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The fixed input data is optional
   if(fixedData == NULL && fixedDataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The implementation only supports 8, 16, 24, and 32-bit counters
   if(r != 0 && r != 8 && r != 16 && r != 24 && r != 32)
      return ERROR_INVALID_PARAMETER;

   //Determine the length, in bytes, of the binary encoding of the counter
   r /= 8;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the CMAC context
   cmacContext = cryptoAllocMem(sizeof(CmacContext));
   //Failed to allocate memory?
   if(cmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize status code
   error = NO_ERROR;

   //K(0) is the initialization vector
   prev = iv;
   prevLen = ivLen;

   //Derive the keying material
   for(i = 1; koLen > 0 && !error; i++)
   {
      //Number of octets in the current block
      n = MIN(koLen, cipherAlgo->blockSize);

      //Initialize CMAC calculation
      error = cmacInit(cmacContext, cipherAlgo, ki, kiLen);

      //Check status code
      if(!error)
      {
         //Encode the counter as a 32-bit big-endian string
         STORE32BE(i, counter);

         //Compute K(i) = PRF(KI, K(i-1) || [i] || FixedInput)
         cmacUpdate(cmacContext, prev, prevLen);
         cmacUpdate(cmacContext, counter + 4 - r, r);
         cmacUpdate(cmacContext, fixedData, fixedDataLen);

         //Finalize CMAC calculation
         error = cmacFinal(cmacContext, ko, n);
      }

      //K(i) becomes the feedback value for the next iteration
      prev = ko;
      prevLen = n;

      //Point to the next block
      ko += n;
      koLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(cmacContext);
#endif

   //Return status code
   return error;
#else
   //CMAC PRF is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief KBKDF key derivation function (double-pipeline mode with HMAC)
 * @param[in] hashAlgo Underlying hash function
 * @param[in] r Length of the binary encoding of the counter, in bits
 * @param[in] ki Key-derivation key KI
 * @param[in] kiLen Length of the key-derivation key, in bytes
 * @param[in] fixedData Fixed input data
 * @param[in] fixedDataLen Length of the fixed input data, in bytes
 * @param[out] ko Derived keying material
 * @param[in] koLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t kbkdfDoublePipelineHmac(const HashAlgo *hashAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen)

{
#if (HMAC_SUPPORT == ENABLED)
   size_t n;
   uint32_t i;
   size_t prevLen;
   const uint8_t *prev;
   uint8_t counter[4];
   uint8_t a[MAX_HASH_DIGEST_SIZE];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || ki == NULL || ko == NULL)
      return ERROR_INVALID_PARAMETER;

   //The fixed input data is optional
   if(fixedData == NULL && fixedDataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The implementation only supports 8, 16, 24, and 32-bit counters
   if(r != 0 && r != 8 && r != 16 && r != 24 && r != 32)
      return ERROR_INVALID_PARAMETER;

   //Determine the length, in bytes, of the binary encoding of the counter
   r /= 8;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //A(0) is the fixed input data
   prev = fixedData;
   prevLen = fixedDataLen;

   //Derive the keying material
   for(i = 1; koLen > 0; i++)
   {
      //Number of octets in the current block
      n = MIN(koLen, hashAlgo->digestSize);

      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Compute A(i) = PRF(KI, A(i-1))
      hmacInit(hmacContext, hashAlgo, ki, kiLen);
      hmacUpdate(hmacContext, prev, prevLen);
      hmacFinal(hmacContext, a);

      //Compute K(i) = PRF(KI, A(i) || [i] || FixedInput)
      hmacInit(hmacContext, hashAlgo, ki, kiLen);
      hmacUpdate(hmacContext, a, hashAlgo->digestSize);
      hmacUpdate(hmacContext, counter + 4 - r, r);
      hmacUpdate(hmacContext, fixedData, fixedDataLen);
      hmacFinal(hmacContext, digest);

      //Save the resulting block
      osMemcpy(ko, digest, n);

      //A(i) is used in the next iteration
      prev = a;
      prevLen = hashAlgo->digestSize;

      //Point to the next block
      ko += n;
      koLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
#else
   //HMAC PRF is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief KBKDF key derivation function (double-pipeline mode with CMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm
 * @param[in] r Length of the binary encoding of the counter, in bits
 * @param[in] ki Key-derivation key KI
 * @param[in] kiLen Length of the key-derivation key, in bytes
 * @param[in] fixedData Fixed input data
 * @param[in] fixedDataLen Length of the fixed input data, in bytes
 * @param[out] ko Derived keying material
 * @param[in] koLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t kbkdfDoublePipelineCmac(const CipherAlgo *cipherAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen)
{
#if (CMAC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint32_t i;
   size_t prevLen;
   const uint8_t *prev;
   uint8_t counter[4];
   uint8_t a[MAX_CIPHER_BLOCK_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   CmacContext *cmacContext;
#else
   CmacContext cmacContext[1];
#endif

   //Check parameters
   if(cipherAlgo == NULL || ki == NULL || ko == NULL)
      return ERROR_INVALID_PARAMETER;

   //The fixed input data is optional
   if(fixedData == NULL && fixedDataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The implementation only supports 8, 16, 24, and 32-bit counters
   if(r != 0 && r != 8 && r != 16 && r != 24 && r != 32)
      return ERROR_INVALID_PARAMETER;

   //Determine the length, in bytes, of the binary encoding of the counter
   r /= 8;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the CMAC context
   cmacContext = cryptoAllocMem(sizeof(CmacContext));
   //Failed to allocate memory?
   if(cmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize status code
   error = NO_ERROR;

   //A(0) is the fixed input data
   prev = fixedData;
   prevLen = fixedDataLen;

   //Derive the keying material
   for(i = 1; koLen > 0 && !error; i++)
   {
      //Number of octets in the current block
      n = MIN(koLen, cipherAlgo->blockSize);

      //Initialize CMAC calculation (first iteration pipeline)
      error = cmacInit(cmacContext, cipherAlgo, ki, kiLen);

      //Check status code
      if(!error)
      {
         //Compute A(i) = PRF(KI, A(i-1))
         cmacUpdate(cmacContext, prev, prevLen);

         //Finalize CMAC calculation (first iteration pipeline)
         error = cmacFinal(cmacContext, a, cipherAlgo->blockSize);
      }

      //Check status code
      if(!error)
      {
         //Initialize CMAC calculation (second iteration pipeline)
         error = cmacInit(cmacContext, cipherAlgo, ki, kiLen);
      }

      //Check status code
      if(!error)
      {
         //Encode the counter as a 32-bit big-endian string
         STORE32BE(i, counter);

         //Compute K(i) = PRF(KI, A(i) || [i] || FixedInput)
         cmacUpdate(cmacContext, a, cipherAlgo->blockSize);
         cmacUpdate(cmacContext, counter + 4 - r, r);
         cmacUpdate(cmacContext, fixedData, fixedDataLen);

         //Finalize CMAC calculation (second iteration pipeline)
         error = cmacFinal(cmacContext, ko, n);
      }

      //A(i) is used in the next iteration
      prev = a;
      prevLen = cipherAlgo->blockSize;

      //Point to the next block
      ko += n;
      koLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(cmacContext);
#endif

   //Return status code
   return error;
#else
   //CMAC PRF is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief KBKDF key derivation function (using KMAC)
 * @param[in] strength Number of bits of security (128 for KMAC128 and
 *   256 for KMAC256)
 * @param[in] ki Key-derivation key KI
 * @param[in] kiLen Length of the key-derivation key, in bytes
 * @param[in] context Context-specific information
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] label Customization string (optional parameter)
 * @param[in] labelLen Length of the customization string, in bytes
 * @param[out] ko Derived keying material
 * @param[in] koLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t kbkdfKmac(uint_t strength, const uint8_t *ki, size_t kiLen,
   const uint8_t *context, size_t contextLen, const char_t *label,
   size_t labelLen, uint8_t *ko, size_t koLen)
{
#if (KMAC_SUPPORT == ENABLED)
   //Compute KO = KMAC(KI, Context, L, Label)
   return kmacCompute(strength, ki, kiLen, context, contextLen, label, labelLen,
      ko, koLen);
#else
   //KMAC PRF is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
