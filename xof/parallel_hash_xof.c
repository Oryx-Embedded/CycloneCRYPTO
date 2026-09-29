/**
 * @file parallel_hash_xof.c
 * @brief ParallelHashXOF (ParallelHash with arbitrary-length output)
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "xof/parallel_hash_xof.h"

//Check crypto library configuration
#if (PARALLEL_HASH_XOF_SUPPORT == ENABLED)


/**
 * @brief Digest a message using ParallelHashXOF
 * @param[in] strength Number of bits of security (128 for ParallelHashXOF128 and
 *   256 for ParallelHashXOF256)
 * @param[in] blockSize Block size in bytes for parallel hashing (B)
 * @param[in] input Pointer to the input string (X)
 * @param[in] inputLen Length of the input string
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data (L)
 * @return Error code
 **/

error_t parallelHashXofCompute(uint_t strength, size_t blockSize,
   const void *input, size_t inputLen, const char_t *custom, size_t customLen,
   uint8_t *output, size_t outputLen)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   ParallelHashXofContext *context;
#else
   ParallelHashXofContext context[1];
#endif

   //Check parameters
   if(input == NULL && inputLen != 0)
      return ERROR_INVALID_PARAMETER;

   if(output == NULL && outputLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the ParallelHashXOF context
   context = cryptoAllocMem(sizeof(ParallelHashXofContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the ParallelHashXOF context
   error = parallelHashXofInit(context, strength, blockSize, custom,
      customLen);

   //Check status code
   if(!error)
   {
      //Absorb the input string
      parallelHashXofAbsorb(context, input, inputLen);
      //Finish absorbing phase
      parallelHashXofFinal(context);
      //Extract data from the squeezing phase
      parallelHashXofSqueeze(context, output, outputLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize ParallelHashXOF context
 * @param[in] context Pointer to the ParallelHashXOF context to initialize
 * @param[in] strength Number of bits of security (128 for ParallelHashXOF128 and
 *   256 for ParallelHashXOF256)
 * @param[in] blockSize Block size in bytes for parallel hashing (B)
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @return Error code
 **/

error_t parallelHashXofInit(ParallelHashXofContext *context, uint_t strength,
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

   //The length of the hash values depends on the ParallelHashXOF variant
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
 * @brief Absorb data
 * @param[in] context Pointer to the ParallelHashXOF context
 * @param[in] data Pointer to the input string
 * @param[in] dataLen Length of the string
 **/

void parallelHashXofAbsorb(ParallelHashXofContext *context, const void *input,
   size_t length)
{
   size_t n;
   uint8_t h[64];

   //Process the input string
   while(length > 0)
   {
      //Limit the number of bytes to process at a time
      n = MIN(context->blockSize - context->blockPos, length);

      //Absorb the input data
      cshakeAbsorb(&context->cshakeContext1, input, n);
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
      input = (uint8_t *) input + n;
      //Remaining bytes to process
      length -= n;
   }
}


/**
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the ParallelHashXOF context
 **/

void parallelHashXofFinal(ParallelHashXofContext *context)
{
   size_t n;
   uint8_t buffer[sizeof(size_t) + 1];

   //Absorb the string representation of n
   cshakeRightEncode(context->blockCount, buffer, &n);
   cshakeAbsorb(&context->cshakeContext2, buffer, n);

   //When used as a XOF, ParallelHash is computed by setting the encoded output
   //length to 0
   cshakeRightEncode(0, buffer, &n);
   cshakeAbsorb(&context->cshakeContext2, buffer, n);

   //Finish absorbing phase
   cshakeFinal(&context->cshakeContext2);
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the ParallelHashXOF context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void parallelHashXofSqueeze(ParallelHashXofContext *context, uint8_t *output,
   size_t length)
{
   //Extract data from the squeezing phase
   cshakeSqueeze(&context->cshakeContext2, output, length);
}

#endif
