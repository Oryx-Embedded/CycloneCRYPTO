/**
 * @file ascon_xof128.c
 * @brief Ascon-XOF128 extendable-output function
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
 * Ascon-XOF128 is an eXtendable Output Functions (XOF), where the output size
 * of the hash of the message can be selected by the user, and the supported
 * security strength is up to 128 bits
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "lwc/ascon_xof128.h"

//Check crypto library configuration
#if (ASCON_XOF128_SUPPORT == ENABLED)


/**
 * @brief Digest a message using Ascon-XOF128
 * @param[in] input Pointer to the input data
 * @param[in] inputLen Length of the input data
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data
 * @return Error code
 **/

error_t asconXof128Compute(const void *input, size_t inputLen, uint8_t *output,
   size_t outputLen)
{
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   AsconXof128Context *context;
#else
   AsconXof128Context context[1];
#endif

   //Check parameters
   if(input == NULL && inputLen != 0)
      return ERROR_INVALID_PARAMETER;

   if(output == NULL && outputLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the Ascon-XOF128 context
   context = cryptoAllocMem(sizeof(AsconXof128Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the Ascon-XOF128 context
   asconXof128Init(context);
   //Absorb input data
   asconXof128Absorb(context, input, inputLen);
   //Finish absorbing phase
   asconXof128Final(context);
   //Extract data from the squeezing phase
   asconXof128Squeeze(context, output, outputLen);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Initialize Ascon-XOF128 context
 * @param[in] context Pointer to the Ascon-XOF128 context to initialize
 **/

void asconXof128Init(AsconXof128Context *context)
{
   //The 320-bit internal state of Ascon-XOF128 is initialized with the
   //concatenation of the 64-bit IV and 256 zeroes
   context->state.x[0] = 0x00CC0003;
   context->state.x[1] = 0x00000800;
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
 * @brief Absorb data
 * @param[in] context Pointer to the Ascon-XOF128 context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void asconXof128Absorb(AsconXof128Context *context, const void *input,
   size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 8 bytes
      n = MIN(length, 8 - context->length);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->length, input, n);
      //Adjust the length of the buffer
      context->length += n;

      //Advance the data pointer
      input = (uint8_t *) input + n;
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
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the Ascon-XOF128 context
 **/

void asconXof128Final(AsconXof128Context *context)
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

   //The squeezing phase begins with an application of Ascon-p[12] to the state
   asconP(&context->state, 12);

   //The value of S[0:63] is then taken as hash block H0
   STORE32LE(context->state.x[0], context->buffer);
   STORE32LE(context->state.x[1], context->buffer + 4);

   //Number of bytes available in the output buffer
   context->length = 8;
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the Ascon-XOF128 context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void asconXof128Squeeze(AsconXof128Context *context, uint8_t *output,
   size_t length)
{
   size_t n;

   //An arbitrary number of output bits can be squeezed out of the state
   while(length > 0)
   {
      //Check whether more data is required
      if(context->length == 0)
      {
         //Apply Ascon-p[12] permutation
         asconP(&context->state, 12);

         //The value of S[0:63] is then taken as hash block H0
         STORE32LE(context->state.x[0], context->buffer);
         STORE32LE(context->state.x[1], context->buffer + 4);

         //Number of bytes available in the output buffer
         context->length = 8;
      }

      //Compute the number of bytes to process at a time
      n = MIN(length, context->length);

      //Copy the output string
      if(output != NULL)
      {
         osMemcpy(output, context->buffer + 8 - context->length, n);
      }

      //Number of bytes available in the output buffer
      context->length -= n;

      //Advance the data pointer
      output = (uint8_t *) output + n;
      //Number of bytes that remains to be written
      length -= n;
   }
}

#endif
