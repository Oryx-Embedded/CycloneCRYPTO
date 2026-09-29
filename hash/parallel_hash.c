/**
 * @file parallel_hash.c
 * @brief ParallelHash hash function
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
 * The purpose of ParallelHash1 is to support the efficient hashing of very
 * long strings, by taking advantage of the parallelism available in modern
 * processors. ParallelHash supports the 128- and 256-bit security strengths
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/parallel_hash.h"

//Check crypto library configuration
#if (PARALLEL_HASH_SUPPORT == ENABLED)


/**
 * @brief Digest a message using ParallelHash
 * @param[in] strength Number of bits of security (128 for ParallelHash128 and
 *   256 for ParallelHash256)
 * @param[in] blockSize Block size in bytes for parallel hashing (B)
 * @param[in] data Pointer to the input string (X)
 * @param[in] dataLen Length of the input string
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @param[out] digest Calculated digest
 * @param[in] digestLen Expected length of the digest (L)
 * @return Error code
 **/

error_t parallelHashCompute(uint_t strength, size_t blockSize,
   const void *data, size_t dataLen, const char_t *custom, size_t customLen,
   uint8_t *digest, size_t digestLen)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   ParallelHashContext *context;
#else
   ParallelHashContext context[1];
#endif

   //Check parameters
   if(data == NULL && dataLen != 0)
      return ERROR_INVALID_PARAMETER;

   if(digest == NULL && digestLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the ParallelHash context
   context = cryptoAllocMem(sizeof(ParallelHashContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the ParallelHash context
   error = parallelHashInit(context, strength, blockSize, custom, customLen);

   //Check status code
   if(!error)
   {
      //Digest the input string
      parallelHashUpdate(context, data, dataLen);
      //Finalize the ParallelHash computation
      parallelHashFinal(context, digest, digestLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize ParallelHash message digest context
 * @param[in] context Pointer to the ParallelHash context to initialize
 * @param[in] strength Number of bits of security (128 for ParallelHash128 and
 *   256 for ParallelHash256)
 * @param[in] blockSize Block size in bytes for parallel hashing (B)
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @return Error code
 **/

error_t parallelHashInit(ParallelHashContext *context, uint_t strength,
   size_t blockSize, const char_t *custom, size_t customLen)
{
   error_t error;
   size_t n;
   uint8_t buffer[sizeof(size_t) + 1];

   //Make sure the ParallelHash context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check block size
   if(blockSize == 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize parameters
   context->strength = strength;
   context->blockSize = blockSize;
   context->blockPos = 0;
   context->blockCount = 0;

   //The length of the hash values depends on the ParallelHash variant
   context->hLen = (strength == 128) ? 32 : 64;

   //Initialize the first cSHAKE instance
   error = cshakeInit(&context->cshakeContext1, strength, "", 0, "", 0);

   //Check status code
   if(!error)
   {
      //Initialize the second cSHAKE instance
      error = cshakeInit(&context->cshakeContext2, strength, "ParallelHash",
         12, custom, customLen);
   }

   //Check status code
   if(!error)
   {
      //Absorb the string representation of B
      cshakeLeftEncode(blockSize, buffer, &n);
      cshakeAbsorb(&context->cshakeContext2, buffer, n);
   }

   //Return status code
   return error;
}


/**
 * @brief Update the ParallelHash context with a portion of the message being hashed
 * @param[in] context Pointer to the ParallelHash context
 * @param[in] data Pointer to the input string
 * @param[in] length Length of the string
 **/

void parallelHashUpdate(ParallelHashContext *context, const void *data, size_t length)
{
   size_t n;
   uint8_t h[64];

   //Process the input string
   while(length > 0)
   {
      //Limit the number of bytes to process at a time
      n = MIN(context->blockSize - context->blockPos, length);

      //Absorb the input data
      cshakeAbsorb(&context->cshakeContext1, data, n);
      context->blockPos += n;

      //ParallelHash operates in a block-by-block fashion
      if(context->blockPos == context->blockSize)
      {
         //Compute the hash value for each block separately
         cshakeFinal(&context->cshakeContext1);
         cshakeSqueeze(&context->cshakeContext1, h, context->hLen);

         //The resulting hash values are combined and passed to cSHAKE
         cshakeAbsorb(&context->cshakeContext2, h, context->hLen);

         //Re-initialize the cSHAKE context
         cshakeInit(&context->cshakeContext1, context->strength, "", 0, "", 0);

         //The block is empty
         context->blockPos = 0;
         //Increment the number of blocks
         context->blockCount++;
      }

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;
   }
}


/**
 * @brief Finish the ParallelHash message digest
 * @param[in] context Pointer to the ParallelHash context
 * @param[out] digest Calculated digest
 * @param[in] length Expected length of the digest (L)
 **/

void parallelHashFinal(ParallelHashContext *context, uint8_t *digest, size_t length)
{
   size_t n;
   uint8_t buffer[sizeof(size_t) + 1];

   //Absorb the string representation of n
   cshakeRightEncode(context->blockCount, buffer, &n);
   cshakeAbsorb(&context->cshakeContext2, buffer, n);

   //Absorb the string representation of L
   cshakeRightEncode(length * 8, buffer, &n);
   cshakeAbsorb(&context->cshakeContext2, buffer, n);

   //Finish absorbing phase
   cshakeFinal(&context->cshakeContext2);
   //Extract data from the squeezing phase
   cshakeSqueeze(&context->cshakeContext2, digest, length);
}

#endif
