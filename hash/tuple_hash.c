/**
 * @file tuple_hash.c
 * @brief TupleHash hash function
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
 * TupleHash is a SHA-3-derived hash function with variable-length output that
 * is designed to simply hash a tuple of input strings
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/tuple_hash.h"

//Check crypto library configuration
#if (TUPLE_HASH_SUPPORT == ENABLED)


/**
 * @brief Digest a message using TupleHash
 * @param[in] strength Number of bits of security (128 for TupleHash128 and
 *   256 for TupleHash256)
 * @param[in] dataFrags Tuple of input strings (X)
 * @param[in] dataNumFrags Number of input strings in the tuple (n)
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @param[out] digest Calculated digest
 * @param[in] digestLen Expected length of the digest (L)
 * @return Error code
 **/

error_t tupleHashCompute(uint_t strength, const DataFrag *dataFrags,
   uint_t dataNumFrags, const char_t *custom, size_t customLen,
   uint8_t *digest, size_t digestLen)
{
   error_t error;
   uint_t i;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   TupleHashContext *context;
#else
   TupleHashContext context[1];
#endif

   //Check parameters
   if(dataFrags == NULL && dataNumFrags != 0)
      return ERROR_INVALID_PARAMETER;

   if(digest == NULL && digestLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the TupleHash context
   context = cryptoAllocMem(sizeof(TupleHashContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the TupleHash context
   error = tupleHashInit(context, strength, custom, customLen);

   //Check status code
   if(!error)
   {
      //Digest the message
      for(i = 0; i < dataNumFrags; i++)
      {
         tupleHashUpdate(context, dataFrags[i].buffer, dataFrags[i].length);
      }

      //Finalize the TupleHash computation
      tupleHashFinal(context, digest, digestLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize TupleHash message digest context
 * @param[in] context Pointer to the TupleHash context to initialize
 * @param[in] strength Number of bits of security (128 for TupleHash128 and
 *   256 for TupleHash256)
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @return Error code
 **/

error_t tupleHashInit(TupleHashContext *context, uint_t strength,
   const char_t *custom, size_t customLen)
{
   //Make sure the TupleHash context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize cSHAKE context
   return cshakeInit(&context->cshakeContext, strength, "TupleHash", 9, custom,
      customLen);
}


/**
 * @brief Update the TupleHash context with a portion of the message being hashed
 * @param[in] context Pointer to the TupleHash context
 * @param[in] data Pointer to the input string
 * @param[in] length Length of the string
 **/

void tupleHashUpdate(TupleHashContext *context, const void *data, size_t length)
{
   size_t n;
   uint8_t buffer[sizeof(size_t) + 1];

   //Absorb the string representation of the input data
   cshakeLeftEncode(length * 8, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);
   cshakeAbsorb(&context->cshakeContext, data, length);
}


/**
 * @brief Finish the TupleHash message digest
 * @param[in] context Pointer to the TupleHash context
 * @param[out] digest Calculated digest
 * @param[in] length Expected length of the digest (L)
 **/

void tupleHashFinal(TupleHashContext *context, uint8_t *digest, size_t length)
{
   size_t n;
   uint8_t buffer[sizeof(size_t) + 1];

   //Absorb the string representation of L
   cshakeRightEncode(length * 8, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);

   //Finish absorbing phase
   cshakeFinal(&context->cshakeContext);
   //Extract data from the squeezing phase
   cshakeSqueeze(&context->cshakeContext, digest, length);
}

#endif
