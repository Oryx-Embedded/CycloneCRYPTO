/**
 * @file ascon_hash256.c
 * @brief Ascon-Hash256 hash function
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
 * Ascon-Hash256 is a cryptographic hash function that produces a 256-bit hash
 * of the input messages, offering a security strength of 128 bits
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "lwc/ascon_hash256.h"

//Check crypto library configuration
#if (ASCON_HASH256_SUPPORT == ENABLED)

//Ascon-Hash256 object identifier (0.0)
const uint8_t ASCON_HASH256_OID[1] = {0x00};

//Common interface for hash algorithms
const HashAlgo asconHash256HashAlgo =
{
   "Ascon-Hash256",
   ASCON_HASH256_OID,
   sizeof(ASCON_HASH256_OID),
   sizeof(AsconHash256Context),
   ASCON_HASH256_BLOCK_SIZE,
   ASCON_HASH256_DIGEST_SIZE,
   ASCON_HASH256_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) asconHash256Compute,
   (HashAlgoInit) asconHash256Init,
   (HashAlgoUpdate) asconHash256Update,
   (HashAlgoFinal) asconHash256Final,
   NULL
};


/**
 * @brief Digest a message using Ascon-Hash256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

__weak_func error_t asconHash256Compute(const void *data, size_t length, uint8_t *digest)
{
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   AsconHash256Context *context;
#else
   AsconHash256Context context[1];
#endif

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   if(digest == NULL)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the Ascon-Hash256 context
   context = cryptoAllocMem(sizeof(AsconHash256Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the Ascon-Hash256 context
   asconHash256Init(context);
   //Digest the message
   asconHash256Update(context, data, length);
   //Finalize the Ascon-Hash256 message digest
   asconHash256Final(context, digest);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Initialize Ascon-Hash256 message digest context
 * @param[in] context Pointer to the Ascon-Hash256 context to initialize
 **/

void asconHash256Init(AsconHash256Context *context)
{
   //The 320-bit internal state of Ascon-Hash256 is initialized with the
   //concatenation of the 64-bit IV and 256 zeroes
   context->state.x[0] = 0x00CC0002;
   context->state.x[1] = 0x00000801;
   context->state.x[2] = 0;
   context->state.x[3] = 0;
   context->state.x[4] = 0;
   context->state.x[5] = 0;
   context->state.x[6] = 0;
   context->state.x[7] = 0;
   context->state.x[8] = 0;
   context->state.x[9] = 0;

   //Apply Ascon-p[12] permutation
   asconP(&context->state, 12);

   //Number of bytes in the buffer
   context->length = 0;
}


/**
 * @brief Update the Ascon-Hash256 context with a portion of the message being hashed
 * @param[in] context Pointer to the Ascon-Hash256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void asconHash256Update(AsconHash256Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 8 bytes
      n = MIN(length, 8 - context->length);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->length, data, n);
      //Adjust the length of the buffer
      context->length += n;

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;

      //The message is partitioned into 64-bit blocks
      if(context->length == 8)
      {
         //Each message block Mi is XORed with the state
         context->state.x[0] ^= LOAD32LE(context->buffer);
         context->state.x[1] ^= LOAD32LE(context->buffer + 4);

         //For all message blocks except the final block Mn,the XOR operation
         //is immediately followed by applying Ascon-p[12] to the state
         asconP(&context->state, 12);

         //The input buffer is empty
         context->length = 0;
      }
   }
}


/**
 * @brief Finish the Ascon-Hash256 message digest
 * @param[in] context Pointer to the Ascon-Hash256 context
 * @param[out] digest Calculated digest
 **/

void asconHash256Final(AsconHash256Context *context, uint8_t *digest)
{
   size_t i;

   //Get the length of the partial block Mn~
   i = context->length;

   //Appends a one followed by one or more zeroes to data
   context->buffer[i++] = 0x01;

   //Partial block Mn~ is padded to a full block Mn
   while(i < 8)
   {
      context->buffer[i++] = 0;
   }

   //The final block Mn is XORed with the state
   context->state.x[0] ^= LOAD32LE(context->buffer);
   context->state.x[1] ^= LOAD32LE(context->buffer + 4);

   //The resulting 256-bit digest is the concatenation of hash blocks
   for(i = 0; i < 4; i++)
   {
      //The state is updated by Ascon-p[12]
      asconP(&context->state, 12);

      //The value of S[0:63] is then taken as hash block Hi
      STORE32LE(context->state.x[0], digest + i * 8);
      STORE32LE(context->state.x[1], digest + i * 8 + 4);
   }
}

#endif
