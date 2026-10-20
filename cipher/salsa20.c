/**
 * @file salsa20.c
 * @brief Salsa20 encryption algorithm
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
#include "cipher/salsa20.h"

//Check crypto library configuration
#if (SALSA20_SUPPORT == ENABLED)

//Salsa20 quarter-round function
#define QUARTER_ROUND(a, b, c, d) \
{ \
   b ^= ROL32(a + d, 7); \
   c ^= ROL32(b + a, 9); \
   d ^= ROL32(c + b, 13); \
   a ^= ROL32(d + c, 18); \
}


/**
 * @brief Initialize Salsa20 context using the supplied key and nonce
 * @param[in] context Pointer to the Salsa20 context to initialize
 * @param[in] nr Number of rounds to be applied (8, 12 or 20)
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes (16 or 32)
 * @param[in] nonce Pointer to the nonce
 * @param[in] nonceLen Length of the nonce, in bytes (8 or 16)
 * @return Error code
 **/

error_t salsa20Init(Salsa20Context *context, uint_t nr, const uint8_t *key,
   size_t keyLen, const uint8_t *nonce, size_t nonceLen)
{
   uint32_t *w;

   //Check parameters
   if(context == NULL || key == NULL || nonce == NULL)
      return ERROR_INVALID_PARAMETER;

   //The number of rounds must be 8, 12 or 20
   if(nr != 8 && nr != 12 && nr != 20)
      return ERROR_INVALID_PARAMETER;

   //Save the number of rounds to be applied
   context->nr = nr;

   //Point to the state
   w = context->state;

   //Check the length of the key
   if(keyLen == 16)
   {
      //Input words 0, 5, 10 and 15 are constants
      w[0] = 0x61707865;
      w[5] = 0x3120646E;
      w[10] = 0x79622D36;
      w[15] = 0x6B206574;

      //Input words 1 through 4 are taken from the 128-bit key, by reading
      //the bytes in little-endian order, in 4-byte chunks
      w[1] = LOAD32LE(key);
      w[2] = LOAD32LE(key + 4);
      w[3] = LOAD32LE(key + 8);
      w[4] = LOAD32LE(key + 12);

      //Input words 11 through 14 are taken from the 128-bit key, again by
      //reading the bytes in little-endian order, in 4-byte chunks
      w[11] = LOAD32LE(key);
      w[12] = LOAD32LE(key + 4);
      w[13] = LOAD32LE(key + 8);
      w[14] = LOAD32LE(key + 12);
   }
   else if(keyLen == 32)
   {
      //Input words 0, 5, 10 and 15 are constants
      w[0] = 0x61707865;
      w[5] = 0x3320646E;
      w[10] = 0x79622D32;
      w[15] = 0x6B206574;

      //Input words 1 through 4 are taken from the first half of the 256-bit
      //key, by reading the bytes in little-endian order, in 4-byte chunks
      w[1] = LOAD32LE(key);
      w[2] = LOAD32LE(key + 4);
      w[3] = LOAD32LE(key + 8);
      w[4] = LOAD32LE(key + 12);

      //Input words 11 through 14 are taken from the second half of the
      //256-bit key, by reading the bytes in little-endian order, in 4-byte
      //chunks
      w[11] = LOAD32LE(key + 16);
      w[12] = LOAD32LE(key + 20);
      w[13] = LOAD32LE(key + 24);
      w[14] = LOAD32LE(key + 28);
   }
   else
   {
      //Invalid key length
      return ERROR_INVALID_PARAMETER;
   }

   //Check the length of the nonce
   if(nonceLen == 8)
   {
      //Input words 6 and 7 are taken from the 64-bit nonce, by reading the
      //bytes in little-endian order, in 4-byte chunks
      w[6] = LOAD32LE(nonce);
      w[7] = LOAD32LE(nonce + 4);

      //Input words 8 and 9 are a block counter, with word 8 overflowing
      //into word 9
      w[8] = 0;
      w[9] = 0;
   }
   else if(nonceLen == 16)
   {
      //Input words 6 to 9 are taken from the 128-bit nonce (which includes
      //the initial value of the block counter), by reading the bytes in
      //little-endian order, in 4-byte chunks
      w[6] = LOAD32LE(nonce);
      w[7] = LOAD32LE(nonce + 4);
      w[8] = LOAD32LE(nonce + 8);
      w[9] = LOAD32LE(nonce + 12);
   }
   else
   {
      //Invalid nonce length
      return ERROR_INVALID_PARAMETER;
   }

   //The keystream block is empty
   context->pos = 0;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Encrypt/decrypt data with the Salsa20 algorithm
 * @param[in] context Pointer to the Salsa20 context
 * @param[in] input Pointer to the data to encrypt/decrypt (optional)
 * @param[in] output Pointer to the resulting data (optional)
 * @param[in] length Number of bytes to be processed
 **/

void salsa20Cipher(Salsa20Context *context, const uint8_t *input,
   uint8_t *output, size_t length)
{
   uint_t i;
   uint_t n;
   uint8_t *k;
   uint8_t block[64];

   //Encryption loop
   while(length > 0)
   {
      //Check whether a new keystream block must be generated
      if(context->pos == 0 || context->pos >= 64)
      {
         //The Salsa20 core function takes a 64-octet input block, so the
         //state words are serialized in little-endian order
         for(i = 0; i < 16; i++)
         {
            STORE32LE(context->state[i], block + i * 4);
         }

         //Salsa20 successively calls the core function, with the same key
         //and nonce, and with successively increasing block counter values
         salsa20ProcessBlock(block, context->keystream, context->nr);

         //Increment block counter
         context->state[8]++;

         //Propagate the carry if necessary
         if(context->state[8] == 0)
         {
            context->state[9]++;
         }

         //Rewind to the beginning of the keystream block
         context->pos = 0;
      }

      //Compute the number of bytes to encrypt/decrypt at a time
      n = MIN(length, 64 - context->pos);

      //Valid output pointer?
      if(output != NULL)
      {
         //Point to the keystream
         k = context->keystream + context->pos;

         //Valid input pointer?
         if(input != NULL)
         {
            //XOR the input data with the keystream
            for(i = 0; i < n; i++)
            {
               output[i] = input[i] ^ k[i];
            }

            //Advance input pointer
            input += n;
         }
         else
         {
            //Output the keystream
            for(i = 0; i < n; i++)
            {
               output[i] = k[i];
            }
         }

         //Advance output pointer
         output += n;
      }

      //Current position in the keystream block
      context->pos += n;

      //Remaining bytes to process
      length -= n;
   }

   //Erase the serialized state (it contains the key)
   osMemset(block, 0, sizeof(block));
}


/**
 * @brief Salsa20 core function
 * @param[in] input Pointer to the 64-octet input block
 * @param[out] output Pointer to the 64-octet output block
 * @param[in] nr Number of rounds to be applied (8, 12 or 20)
 **/

void salsa20ProcessBlock(const uint8_t *input, uint8_t *output, uint_t nr)
{
   uint_t i;
   uint32_t x[16];

   //Copy the input words to the working state
   for(i = 0; i < 16; i++)
   {
      x[i] = LOAD32LE(input + i * 4);
   }

   //The Salsa20 core function alternates between column rounds and row rounds
   for(i = 0; i < nr; i += 2)
   {
      //The column round function modifies the columns of the matrix in parallel
      //by feeding a permutation of each column through the quarter round function
      QUARTER_ROUND(x[0], x[4], x[8], x[12]);
      QUARTER_ROUND(x[5], x[9], x[13], x[1]);
      QUARTER_ROUND(x[10], x[14], x[2], x[6]);
      QUARTER_ROUND(x[15], x[3], x[7], x[11]);

      //The row round function modifies the rows of the matrix in parallel by
      //feeding a permutation of each row through the quarter round function
      QUARTER_ROUND(x[0], x[1], x[2], x[3]);
      QUARTER_ROUND(x[5], x[6], x[7], x[4]);
      QUARTER_ROUND(x[10], x[11], x[8], x[9]);
      QUARTER_ROUND(x[15], x[12], x[13], x[14]);
   }

   //Add the original input words to the output words
   for(i = 0; i < 16; i++)
   {
      x[i] += LOAD32LE(input + i * 4);
      STORE32LE(x[i], output + i * 4);
   }
}


/**
 * @brief Release Salsa20 context
 * @param[in] context Pointer to the Salsa20 context
 **/

void salsa20Deinit(Salsa20Context *context)
{
   //Clear Salsa20 context
   osMemset(context, 0, sizeof(Salsa20Context));
}

#endif
