/**
 * @file ascon_cxof128.c
 * @brief Ascon-CXOF128 customizable extendable-output function
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
 * Ascon-CXOF128 is a customized eXtendable Output Functions (XOF) that allows
 * users to specify a customization string and choose the output size of the
 * message hash. It supports a security strength of up to 128 bits
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "lwc/ascon_cxof128.h"

//Check crypto library configuration
#if (ASCON_CXOF128_SUPPORT == ENABLED)


/**
 * @brief Digest a message using Ascon-CXOF128
 * @param[in] input Pointer to the input data
 * @param[in] inputLen Length of the input data
 * @param[in] custom Customization string (Z)
 * @param[in] customLen Length of the customization string
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data
 * @return Error code
 **/

error_t asconCxof128Compute(const void *input, size_t inputLen,
   const char_t *custom, size_t customLen, uint8_t *output, size_t outputLen)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   AsconCxof128Context *context;
#else
   AsconCxof128Context context[1];
#endif

   //Check parameters
   if(input == NULL && inputLen != 0)
      return ERROR_INVALID_PARAMETER;

   if(output == NULL && outputLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the Ascon-CXOF128 context
   context = cryptoAllocMem(sizeof(AsconCxof128Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the Ascon-CXOF128 context
   error = asconCxof128Init(context, custom, customLen);

   //Check status code
   if(!error)
   {
      //Absorb input data
      asconCxof128Absorb(context, input, inputLen);
      //Finish absorbing phase
      asconCxof128Final(context);
      //Extract data from the squeezing phase
      asconCxof128Squeeze(context, output, outputLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize Ascon-CXOF128 context
 * @param[in] context Pointer to the Ascon-CXOF128 context to initialize
 * @param[in] custom Customization string (Z)
 * @param[in] customLen Length of the customization string, in bytes
 * @return Error code
 **/

error_t asconCxof128Init(AsconCxof128Context *context, const char_t *custom,
   size_t customLen)
{
   //Make sure the Ascon-CXOF128 context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the customization string shall be at most 2048 bits
   if(customLen > 256)
      return ERROR_INVALID_LENGTH;

   //For domain separation, Ascon-CXOF128 uses a different IV than Ascon-XOF128
   context->state.x[0] = 0x00CC0004;
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

   //Z0 is a 64-bit integer that represents the bit-length of the customization
   //string
   STORE64LE(customLen * 8, context->buffer);

   //Update the state with Z0
   context->state.x[0] ^= LOAD32LE(context->buffer);
   context->state.x[1] ^= LOAD32LE(context->buffer + 4);

   //Apply Ascon-p[12] permutation
   asconP(&context->state, 12);

   //The customization string Z is parsed into blocks
   while(customLen >= 8)
   {
      //Update the state with Zi
      context->state.x[0] ^= LOAD32LE(custom);
      context->state.x[1] ^= LOAD32LE(custom + 4);

      //Apply Ascon-p[12] permutation
      asconP(&context->state, 12);

      //Next block
      custom += 8;
      customLen -= 8;
   }

   //Partial block Zm~ is padded to a full block Zm
   osMemset(context->buffer, 0, 8);
   osMemcpy(context->buffer, custom, customLen);
   context->buffer[customLen] = 0x01;

   //Update the state with Zm
   context->state.x[0] ^= LOAD32LE(context->buffer);
   context->state.x[1] ^= LOAD32LE(context->buffer + 4);

   //Apply Ascon-p[12] permutation
   asconP(&context->state, 12);

   //Number of bytes in the buffer
   context->length = 0;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the Ascon-CXOF128 context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void asconCxof128Absorb(AsconCxof128Context *context, const void *input,
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
 * @param[in] context Pointer to the Ascon-CXOF128 context
 **/

void asconCxof128Final(AsconCxof128Context *context)
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
 * @param[in] context Pointer to the Ascon-CXOF128 context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void asconCxof128Squeeze(AsconCxof128Context *context, uint8_t *output,
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
