/**
 * @file xcbc_mac.c
 * @brief XCBC-MAC message authentication code
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
 * @section Description
 *
 * XCBC-MAC is a block cipher-based MAC algorithm specified in NIST SP 800-38B
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "mac/xcbc_mac.h"

//Check crypto library configuration
#if (XCBC_MAC_SUPPORT == ENABLED)


/**
 * @brief Compute XCBC-MAC using the specified cipher algorithm
 * @param[in] cipher Cipher algorithm used to compute XCBC-MAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @param[in] data Pointer to the input message
 * @param[in] dataLen Length of the input data
 * @param[out] mac Calculated MAC value
 * @param[in] macLen Expected length of the MAC
 * @return Error code
 **/

error_t xcbcMacCompute(const CipherAlgo *cipher, const void *key, size_t keyLen,
   const void *data, size_t dataLen, uint8_t *mac, size_t macLen)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   XcbcMacContext *context;
#else
   XcbcMacContext context[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the XCBC-MAC context
   context = cryptoAllocMem(sizeof(XcbcMacContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the XCBC-MAC context
   error = xcbcMacInit(context, cipher, key, keyLen);

   //Check status code
   if(!error)
   {
      //Digest the message
      xcbcMacUpdate(context, data, dataLen);
      //Finalize the XCBC-MAC computation
      error = xcbcMacFinal(context, mac, macLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize XCBC-MAC calculation
 * @param[in] context Pointer to the XCBC-MAC context to initialize
 * @param[in] cipher Cipher algorithm used to compute XCBC-MAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @return Error code
 **/

error_t xcbcMacInit(XcbcMacContext *context, const CipherAlgo *cipher,
   const void *key, size_t keyLen)
{
   error_t error;

   //Check parameters
   if(context == NULL || cipher == NULL)
      return ERROR_INVALID_PARAMETER;

   //XCBC-MAC uses a block cipher for encryption
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK)
      return ERROR_INVALID_PARAMETER;

   //Cipher algorithm used to compute XCBC-MAC
   context->cipher = cipher;

   //Load the 128-bit secret K
   error = cipher->init(&context->cipherContext, key, keyLen);
   //Any error to report?
   if(error)
      return error;

   //Derive three 128-bit keys (K1, K2 and K3) from the 128-bit secret key K
   osMemset(context->k1, 0x01, cipher->blockSize);
   osMemset(context->k2, 0x02, cipher->blockSize);
   osMemset(context->k3, 0x03, cipher->blockSize);

   //Let K1 = 0x01010101010101010101010101010101 encrypted with key K
   cipher->encryptBlock(&context->cipherContext, context->k1, context->k1);
   //Let K2 = 0x02020202020202020202020202020202 encrypted with key K
   cipher->encryptBlock(&context->cipherContext, context->k2, context->k2);
   //Let K3 = 0x03030303030303030303030303030303 encrypted with key K
   cipher->encryptBlock(&context->cipherContext, context->k3, context->k3);

   //Release cipher context
   cipher->deinit(&context->cipherContext);

   //Load the 128-bit secret K1
   error = cipher->init(&context->cipherContext, context->k1,
      cipher->blockSize);
   //Any error to report?
   if(error)
      return error;

   //Reset XCBC-MAC context
   xcbcMacReset(context);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Reset XCBC-MAC context
 * @param[in] context Pointer to the XCBC-MAC context
 **/

void xcbcMacReset(XcbcMacContext *context)
{
   //Clear input buffer
   osMemset(context->buffer, 0, context->cipher->blockSize);
   //Number of bytes in the buffer
   context->bufferLength = 0;

   //Define E[0] = 0x00000000000000000000000000000000
   osMemset(context->mac, 0, context->cipher->blockSize);
}


/**
 * @brief Update the XCBC-MAC context with a portion of the message being hashed
 * @param[in] context Pointer to the XCBC-MAC context
 * @param[in] data Pointer to the input data
 * @param[in] dataLen Length of the buffer
 **/

void xcbcMacUpdate(XcbcMacContext *context, const void *data, size_t dataLen)
{
   size_t n;

   //Process the incoming data
   while(dataLen > 0)
   {
      //Process message block by block
      if(context->bufferLength == context->cipher->blockSize)
      {
         //XOR M[i] with E[i-1]
         xcbcMacXorBlock(context->buffer, context->buffer, context->mac,
            context->cipher->blockSize);

         //Then encrypt the result with key K1, yielding E[i]
         context->cipher->encryptBlock(&context->cipherContext, context->buffer,
            context->mac);

         //Empty the buffer
         context->bufferLength = 0;
      }

      //The message is partitioned into complete blocks
      n = MIN(dataLen, context->cipher->blockSize - context->bufferLength);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->bufferLength, data, n);
      //Update the length of the buffer
      context->bufferLength += n;

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      dataLen -= n;
   }
}


/**
 * @brief Finish the XCBC-MAC calculation
 * @param[in] context Pointer to the XCBC-MAC context
 * @param[out] mac Calculated MAC value (optional parameter)
 * @param[in] macLen Expected length of the MAC
 * @return Error code
 **/

error_t xcbcMacFinal(XcbcMacContext *context, uint8_t *mac, size_t macLen)
{
   //Make sure the XCBC-MAC context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the MAC
   if(macLen < 1 || macLen > context->cipher->blockSize)
      return ERROR_INVALID_PARAMETER;

   //Check whether the block size of M[n] is 128 bits
   if(context->bufferLength >= context->cipher->blockSize)
   {
      //XOR M[n] with E[n-1] and key K2
      xcbcMacXorBlock(context->buffer, context->buffer, context->mac,
         context->cipher->blockSize);

      xcbcMacXorBlock(context->buffer, context->buffer, context->k2,
         context->cipher->blockSize);

      //Then encrypt the result with key K1, yielding E[n]
      context->cipher->encryptBlock(&context->cipherContext, context->buffer,
         context->mac);
   }
   else
   {
      //Pad M[n] with a single "1" bit
      context->buffer[context->bufferLength++] = 0x80;

      //Append the number of "0" bits (possibly none) required to increase
      //M[n]'s block size to 128 bits
      while(context->bufferLength < context->cipher->blockSize)
      {
         context->buffer[context->bufferLength++] = 0x00;
      }

      //XOR M[n] with E[n-1] and key K3
      xcbcMacXorBlock(context->buffer, context->buffer, context->mac,
         context->cipher->blockSize);

      xcbcMacXorBlock(context->buffer, context->buffer, context->k3,
         context->cipher->blockSize);

      //Then encrypt the result with key K1, yielding E[n]
      context->cipher->encryptBlock(&context->cipherContext, context->buffer,
         context->mac);
   }

   //Copy the resulting MAC value
   if(mac != NULL)
   {
      //The authenticator value is the leftmost bits of the 128-bit E[n]
      osMemcpy(mac, context->mac, macLen);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release XCBC-MAC context
 * @param[in] context Pointer to the XCBC-MAC context
 **/

void xcbcMacDeinit(XcbcMacContext *context)
{
   //Make sure the XCBC-MAC context is valid
   if(context != NULL)
   {
      //Release cipher context
      context->cipher->deinit(&context->cipherContext);

      //Clear XCBC-MAC context
      osMemset(context, 0, sizeof(XcbcMacContext));
   }
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First input block
 * @param[in] b Second input block
 * @param[in] n Size of the block, in bytes
 **/

void xcbcMacXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
{
   size_t i;

   //Perform XOR operation
   for(i = 0; i < n; i++)
   {
      x[i] = a[i] ^ b[i];
   }
}

#endif
