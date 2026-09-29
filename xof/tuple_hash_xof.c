/**
 * @file tuple_hash_xof.c
 * @brief TupleHashXOF (TupleHash with arbitrary-length output)
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
#include "xof/tuple_hash_xof.h"

//Check crypto library configuration
#if (TUPLE_HASH_XOF_SUPPORT == ENABLED)


/**
 * @brief Digest a message using TupleHashXOF
 * @param[in] strength Number of bits of security (128 for TupleHashXOF128 and
 *   256 for TupleHashXOF256)
 * @param[in] key Pointer to the secret key (K)
 * @param[in] keyLen Length of the secret key
 * @param[in] inputFrags Tuple of input strings (X)
 * @param[in] inputNumFrags Number of input strings in the tuple (n)
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data (L)
 * @return Error code
 **/

error_t tupleHashXofCompute(uint_t strength, const DataFrag *inputFrags,
   uint_t inputNumFrags, const char_t *custom, size_t customLen,
   uint8_t *output, size_t outputLen)
{
   error_t error;
   uint_t i;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   TupleHashXofContext *context;
#else
   TupleHashXofContext context[1];
#endif

   //Check parameters
   if(inputFrags == NULL && inputNumFrags != 0)
      return ERROR_INVALID_PARAMETER;

   if(output == NULL && outputLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the TupleHashXOF context
   context = cryptoAllocMem(sizeof(TupleHashXofContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the TupleHashXOF context
   error = tupleHashXofInit(context, strength, custom, customLen);

   //Check status code
   if(!error)
   {
      //Absorb input data
      for(i = 0; i < inputNumFrags; i++)
      {
         tupleHashXofAbsorb(context, inputFrags[i].buffer,
            inputFrags[i].length);
      }

      //Finish absorbing phase
      tupleHashXofFinal(context);
      //Extract data from the squeezing phase
      tupleHashXofSqueeze(context, output, outputLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize TupleHashXOF context
 * @param[in] context Pointer to the TupleHashXOF context to initialize
 * @param[in] strength Number of bits of security (128 for TupleHashXOF128 and
 *   256 for TupleHashXOF256)
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @return Error code
 **/

error_t tupleHashXofInit(TupleHashXofContext *context, uint_t strength,
   const char_t *custom, size_t customLen)
{
   error_t error;

   //Make sure the TupleHashXOF context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize cSHAKE context
   return cshakeInit(&context->cshakeContext, strength, "TupleHash", 9, custom,
      customLen);
}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the TupleHashXOF context
 * @param[in] input Pointer to the input string
 * @param[in] length Length of the string
 **/

void tupleHashXofAbsorb(TupleHashXofContext *context, const void *input,
   size_t length)
{
   size_t n;
   uint8_t buffer[sizeof(size_t) + 1];

   //Absorb the string representation of the input data
   cshakeLeftEncode(length * 8, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);
   cshakeAbsorb(&context->cshakeContext, input, length);
}


/**
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the TupleHashXOF context
 **/

void tupleHashXofFinal(TupleHashXofContext *context)
{
   uint8_t buffer[2];

   //When used as a XOF, TupleHash is computed by setting the encoded output
   //length to 0
   buffer[0] = 0;
   buffer[1] = 1;
   cshakeAbsorb(&context->cshakeContext, buffer, 2);

   //Finish absorbing phase
   cshakeFinal(&context->cshakeContext);
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the TupleHashXOF context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void tupleHashXofSqueeze(TupleHashXofContext *context, uint8_t *output,
   size_t length)
{
   //Extract data from the squeezing phase
   cshakeSqueeze(&context->cshakeContext, output, length);
}

#endif
