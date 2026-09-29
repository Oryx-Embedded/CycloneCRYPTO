/**
 * @file ike_kdf.c
 * @brief IKEv2 key derivation functions
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
#include "kdf/ike_kdf.h"

//Check crypto library configuration
#if (IKE_KDF_SUPPORT == ENABLED)


/**
 * @brief Pseudorandom function (prf function)
 * @param[in] macAlgo PRF algorithm (CMAC, HMAC, KMAC or XCBC-MAC)
 * @param[in] hashAlgo Underlying hash function (for HMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm (for CMAC and XCBC-MAC)
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes
 * @param[in] data Pointer to the data
 * @param[in] dataLen Length of the data, in bytes
 * @param[in] output Pseudorandom output
 * @return Error code
 **/

error_t ikePrf(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const uint8_t *data, size_t dataLen, uint8_t *output)
{
   error_t error;
   DataFrag dataFrags[1];

   //Check parameters
   if(data == NULL && dataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The data fits in a single fragment
   dataFrags[0].buffer = data;
   dataFrags[0].length = dataLen;

   //Perform PRF calculation
   error = ikePrfEx(macAlgo, hashAlgo, cipherAlgo, key, keyLen, dataFrags,
      arraysize(dataFrags), output);

   //Return status code
   return error;
}


/**
 * @brief Pseudorandom function (prf function)
 * @param[in] macAlgo PRF algorithm (CMAC, HMAC, KMAC or XCBC-MAC)
 * @param[in] hashAlgo Underlying hash function (for HMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm (for CMAC and XCBC-MAC)
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes
 * @param[in] dataFrags Array of fragments representing the data
 * @param[in] dataNumFrags Number of fragments representing the data
 * @param[in] output Pseudorandom output
 * @return Error code
 **/

error_t ikePrfEx(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const DataFrag *dataFrags, uint_t dataNumFrags, uint8_t *output)
{
   error_t error;
   uint_t i;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   IkePrfContext *context;
#else
   IkePrfContext context[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the IKE PRF context
   context = cryptoAllocMem(sizeof(IkePrfContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize PRF calculation
   error = ikePrfInit(context, macAlgo, hashAlgo, cipherAlgo, key, keyLen);

   //Check status code
   if(!error)
   {
      //Process the data
      for(i = 0; i < dataNumFrags; i++)
      {
         ikePrfUpdate(context, dataFrags[i].buffer, dataFrags[i].length);
      }

      //Finalize PRF calculation
      error = ikePrfFinal(context, output, context->outputLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Function that outputs a pseudorandom stream (prf+ function)
 * @param[in] macAlgo PRF algorithm (CMAC, HMAC, KMAC or XCBC-MAC)
 * @param[in] hashAlgo Underlying hash function (for HMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm (for CMAC and XCBC-MAC)
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes
 * @param[in] data Pointer to the data
 * @param[in] dataLen Length of the data, in bytes
 * @param[out] output Pseudorandom output stream
 * @param[in] outputLen Desired length of the pseudorandom output stream
 * @return Error code
 **/

error_t ikePrfPlus(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const uint8_t *data, size_t dataLen, uint8_t *output,
   size_t outputLen)
{
   error_t error;
   DataFrag dataFrags[1];

   //Check parameters
   if(data == NULL && dataLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The data fits in a single fragment
   dataFrags[0].buffer = data;
   dataFrags[0].length = dataLen;

   //Perform PRF calculation
   error = ikePrfPlusEx(macAlgo, hashAlgo, cipherAlgo, key, keyLen, dataFrags,
      arraysize(dataFrags), output, outputLen);

   //Return status code
   return error;
}


/**
 * @brief Function that outputs a pseudorandom stream (prf+ function)
 * @param[in] macAlgo PRF algorithm (CMAC, HMAC, KMAC or XCBC-MAC)
 * @param[in] hashAlgo Underlying hash function (for HMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm (for CMAC and XCBC-MAC)
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes
 * @param[in] dataFrags Array of fragments representing the data
 * @param[in] dataNumFrags Number of fragments representing the data
 * @param[out] output Pseudorandom output stream
 * @param[in] outputLen Desired length of the pseudorandom output stream
 * @return Error code
 **/

error_t ikePrfPlusEx(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const DataFrag *dataFrags, uint_t dataNumFrags, uint8_t *output,
   size_t outputLen)
{
   error_t error;
   uint_t i;
   size_t n;
   uint8_t c;
   uint8_t t[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   IkePrfContext *context;
#else
   IkePrfContext context[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the IKE PRF context
   context = cryptoAllocMem(sizeof(IkePrfContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize counter value
   c = 1;

   //Variable-length output PRF?
   if(macAlgo == MAC_ALGO_KMAC128 || macAlgo == MAC_ALGO_KMAC256)
   {
      //A single call to the PRF can produce as many pseudorandom bits as
      //needed
      error = ikePrfInit(context, macAlgo, NULL, NULL, key, keyLen);

      //Check status code
      if(!error)
      {
         //Compute prf+ (K,S) = prf (K, S | 0x01)
         for(i = 0; i < dataNumFrags; i++)
         {
            ikePrfUpdate(context, dataFrags[i].buffer, dataFrags[i].length);
         }

         ikePrfUpdate(context, &c, sizeof(uint8_t));

         //Finalize PRF calculation
         error = ikePrfFinal(context, output, outputLen);
      }
   }
   else
   {
      //Initialize status code
      error = NO_ERROR;

      //Since the amount of keying material needed may be greater than the size
      //of the output of the PRF, the PRF is used iteratively
      while(outputLen > 0)
      {
         //The prf+ function is not defined beyond 255 times the size of the
         //prf function output (refer to RFC 7296, section 2.13)
         if(c == 0)
            return ERROR_INVALID_LENGTH;

         //Initialize PRF calculation
         error = ikePrfInit(context, macAlgo, hashAlgo, cipherAlgo, key,
            keyLen);
         //Any error to report?
         if(error)
            break;

         //Compute T(n) = prf(K, T(n-1) | S | c)
         if(c > 1)
         {
            ikePrfUpdate(context, t, context->outputLen);
         }

         for(i = 0; i < dataNumFrags; i++)
         {
            ikePrfUpdate(context, dataFrags[i].buffer, dataFrags[i].length);
         }

         ikePrfUpdate(context, &c, sizeof(uint8_t));

         //Finalize PRF calculation
         error = ikePrfFinal(context, t, context->outputLen);
         //Any error to report?
         if(error)
            break;

         //Calculate the number of bytes to copy
         n = MIN(outputLen, context->outputLen);
         //Copy the output of the PRF
         osMemcpy(output, t, n);

         //This process is repeated until enough key material is available
         output += n;
         outputLen -= n;

         //Increment counter value
         c++;
      }
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize PRF calculation
 * @param[in] context Pointer to the IKE PRF context
 * @param[in] macAlgo PRF algorithm (CMAC, HMAC, KMAC or XCBC-MAC)
 * @param[in] hashAlgo Underlying hash function (for HMAC)
 * @param[in] cipherAlgo Underlying cipher algorithm (for CMAC and XCBC-MAC)
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes
 * @return Error code
 **/

error_t ikePrfInit(IkePrfContext *context, MacAlgo macAlgo,
   const HashAlgo *hashAlgo, const CipherAlgo *cipherAlgo, const uint8_t *key,
   size_t keyLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (CMAC_SUPPORT == ENABLED)
   //CMAC PRF algorithm?
   if(macAlgo == MAC_ALGO_CMAC && cipherAlgo != NULL &&
      cipherAlgo->blockSize == 16)
   {
      uint8_t k[16];
      CmacContext *cmacContext;

      //Save PRF algorithm
      context->macAlgo = MAC_ALGO_CMAC;
      context->outputLen = 16;

      //Point to the CMAC context
      cmacContext = &context->macContext.cmacContext;

      //Derive the 128-bit key K from the variable-length key VK
      if(keyLen == 16)
      {
         //If the key VK is exactly 128 bits, then we use it as-is
         osMemcpy(k, key, keyLen);
      }
      else
      {
         //If the key VK is longer or shorter than 128 bits, then we derive the
         //key K by applying the AES-CMAC algorithm using the 128-bit all-zero
         //string as the key and VK as the input message (refer to RFC 4615,
         //section 3)
         osMemset(k, 0, 16);

         //Initialize CMAC calculation
         error = cmacInit(cmacContext, cipherAlgo, k, 16);

         //Check status code
         if(!error)
         {
            //Compute K = AES-CMAC(0^128, VK, VKlen)
            cmacUpdate(cmacContext, key, keyLen);

            //Derive the 128-bit key K
            error = cmacFinal(cmacContext, k, 16);
         }
      }

      //Check status code
      if(!error)
      {
         //We apply the AES-CMAC algorithm using K as the key
         error = cmacInit(cmacContext, cipherAlgo, k, 16);
      }
   }
   else
#endif
#if (HMAC_SUPPORT == ENABLED)
   //HMAC PRF algorithm?
   if(macAlgo == MAC_ALGO_HMAC && hashAlgo != NULL)
   {
      //Save PRF algorithm
      context->macAlgo = MAC_ALGO_HMAC;
      context->outputLen = hashAlgo->digestSize;

      //Initialize HMAC calculation
      error = hmacInit(&context->macContext.hmacContext, hashAlgo, key, keyLen);
   }
   else
#endif
#if (KMAC_SUPPORT == ENABLED)
   //KMAC PRF algorithm?
   if(macAlgo == MAC_ALGO_KMAC128 || macAlgo == MAC_ALGO_KMAC256)
   {
      uint_t strength;

      //Save PRF algorithm
      context->macAlgo = macAlgo;

      //The security strength depends on the KMAC variant
      if(macAlgo == MAC_ALGO_KMAC128)
      {
         strength = 128;
         context->outputLen = 32;
      }
      else
      {
         strength = 256;
         context->outputLen = 64;
      }

      //KMAC's customization string C is always empty
      error = kmacInit(&context->macContext.kmacContext, strength, key, keyLen,
         NULL, 0);
   }
   else
#endif
#if (XCBC_MAC_SUPPORT == ENABLED)
   //XCBC-MAC PRF algorithm?
   if(macAlgo == MAC_ALGO_XCBC_MAC && cipherAlgo != NULL &&
      cipherAlgo->blockSize == 16)
   {
      uint8_t k[16];
      XcbcMacContext *xcbcMacContext;

      //Save PRF algorithm
      context->macAlgo = MAC_ALGO_XCBC_MAC;
      context->outputLen = 16;

      //Point to the XCBC-MAC context
      xcbcMacContext = &context->macContext.xcbcMacContext;

      //Derive the 128-bit key K from the variable-length key VK
      if(keyLen == 16)
      {
         //If the key is exactly 128 bits long, use it as-is
         osMemcpy(k, key, keyLen);
      }
      else if(keyLen < 16)
      {
         //If the key has fewer than 128 bits, lengthen it to exactly 128 bits
         //by padding it on the right with zero bits
         osMemcpy(k, key, keyLen);
         osMemset(k + keyLen, 0, 16 - keyLen);
      }
      else
      {
         //If the key is 129 bits or longer, shorten it to exactly 128 bits
         //by performing the steps in AES-XCBC-PRF-128 (refer to RFC 4434,
         //section 2)
         osMemset(k, 0, 16);

         //The key is 128 zero bits
         error = xcbcMacInit(xcbcMacContext, cipherAlgo, k, 16);

         //Check status code
         if(!error)
         {
            //The message is the too-long current key
            xcbcMacUpdate(xcbcMacContext, key, keyLen);

            //Derive the 128-bit key K
            error = xcbcMacFinal(xcbcMacContext, k, 16);
         }
      }

      //Check status code
      if(!error)
      {
         //We apply the XCBC-MAC algorithm using K as the key
         error = xcbcMacInit(xcbcMacContext, cipherAlgo, k, 16);
      }
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Update PRF calculation
 * @param[in] context Pointer to the IKE PRF context
 * @param[in] data Pointer to the data
 * @param[in] dataLen Length of the data, in bytes
 **/

void ikePrfUpdate(IkePrfContext *context, const uint8_t *data, size_t dataLen)
{
#if (CMAC_SUPPORT == ENABLED)
   //CMAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_CMAC)
   {
      //Update CMAC calculation
      cmacUpdate(&context->macContext.cmacContext, data, dataLen);
   }
   else
#endif
#if (HMAC_SUPPORT == ENABLED)
   //HMAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_HMAC)
   {
      //Update HMAC calculation
      hmacUpdate(&context->macContext.hmacContext, data, dataLen);
   }
   else
#endif
#if (KMAC_SUPPORT == ENABLED)
   //KMAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_KMAC128 ||
      context->macAlgo == MAC_ALGO_KMAC256)
   {
      //Update KMAC calculation
      kmacUpdate(&context->macContext.kmacContext, data, dataLen);
   }
   else
#endif
#if (XCBC_MAC_SUPPORT == ENABLED)
   //XCBC-MAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_XCBC_MAC)
   {
      //Update XCBC-MAC calculation
      xcbcMacUpdate(&context->macContext.xcbcMacContext, data, dataLen);
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      //Just for sanity
   }
}


/**
 * @brief Finalize PRF calculation
 * @param[in] context Pointer to the IKE PRF context
 * @param[out] output Pseudorandom output
 * @param[in] outputLen Desired length of the pseudorandom output stream
 * @return Error code
 **/

error_t ikePrfFinal(IkePrfContext *context, uint8_t *output, size_t outputLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (CMAC_SUPPORT == ENABLED)
   //CMAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_CMAC)
   {
      //Finalize CMAC calculation
      error = cmacFinal(&context->macContext.cmacContext, output, outputLen);
   }
   else
#endif
#if (HMAC_SUPPORT == ENABLED)
   //HMAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_HMAC)
   {
      //Finalize HMAC calculation
      hmacFinal(&context->macContext.hmacContext, output);
   }
   else
#endif
#if (KMAC_SUPPORT == ENABLED)
   //KMAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_KMAC128 ||
      context->macAlgo == MAC_ALGO_KMAC256)
   {
      //Finalize KMAC calculation
      error = kmacFinal(&context->macContext.kmacContext, output, outputLen);
   }
   else
#endif
#if (XCBC_MAC_SUPPORT == ENABLED)
   //XCBC-MAC PRF algorithm?
   if(context->macAlgo == MAC_ALGO_XCBC_MAC)
   {
      //Finalize XCBC-MAC calculation
      error = xcbcMacFinal(&context->macContext.xcbcMacContext, output,
         outputLen);
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
