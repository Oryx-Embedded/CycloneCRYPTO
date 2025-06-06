/**
 * @file tea.c
 * @brief TEA (Tiny Encryption Algorithm)
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/tea.h"

//TEA magic constant
#define DELTA 0x9E3779B9

//Check crypto library configuration
#if (TEA_SUPPORT == ENABLED)


//Common interface for encryption algorithms
const CipherAlgo teaCipherAlgo =
{
   "TEA",
   sizeof(TeaContext),
   CIPHER_ALGO_TYPE_BLOCK,
   TEA_BLOCK_SIZE,
   (CipherAlgoInit) teaInit,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) teaEncryptBlock,
   (CipherAlgoDecryptBlock) teaDecryptBlock,
   (CipherAlgoDeinit) teaDeinit
};


/**
 * @brief Key expansion
 * @param[in] context Pointer to the TEA context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t teaInit(TeaContext *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid key length?
   if(keyLen != 16)
      return ERROR_INVALID_KEY_LENGTH;

   //Copy the 128-bit key
   context->k[0] = LOAD32BE(key);
   context->k[1] = LOAD32BE(key + 4);
   context->k[2] = LOAD32BE(key + 8);
   context->k[3] = LOAD32BE(key + 12);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using TEA algorithm
 * @param[in] context Pointer to the TEA context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void teaEncryptBlock(TeaContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t y;
   uint32_t z;
   uint32_t sum;

   //Initialize variable
   sum = 0;

   //The 8 bytes of plaintext are split into 2 words
   y = LOAD32BE(input);
   z = LOAD32BE(input + 4);

   //Apply 32 rounds
   for(i = 0; i < TEA_NB_ROUNDS; i++)
   {
      sum += DELTA;
      y += ((z << 4) + context->k[0]) ^ (z + sum) ^ ((z >> 5) + context->k[1]);
      z += ((y << 4) + context->k[2]) ^ (y + sum) ^ ((y >> 5) + context->k[3]);
   }

   //The 2 words of ciphertext are then written as 8 bytes
   STORE32BE(y, output);
   STORE32BE(z, output + 4);
}


/**
 * @brief Decrypt a 16-byte block using TEA algorithm
 * @param[in] context Pointer to the TEA context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void teaDecryptBlock(TeaContext *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t y;
   uint32_t z;
   uint32_t sum;

   //Initialize variable
   sum = (DELTA & 0x07FFFFFF) << 5;

   //The 8 bytes of ciphertext are split into 2 words
   y = LOAD32BE(input);
   z = LOAD32BE(input + 4);

   //Apply 32 rounds
   for(i = 0; i < TEA_NB_ROUNDS; i++)
   {
      z -= ((y << 4) + context->k[2]) ^ (y + sum) ^ ((y >> 5) + context->k[3]);
      y -= ((z << 4) + context->k[0]) ^ (z + sum) ^ ((z >> 5) + context->k[1]);
      sum -= DELTA;
   }

   //The 2 words of plaintext are then written as 8 bytes
   STORE32BE(y, output);
   STORE32BE(z, output + 4);
}


/**
 * @brief Release TEA context
 * @param[in] context Pointer to the TEA context
 **/

void teaDeinit(TeaContext *context)
{
   //Clear TEA context
   osMemset(context, 0, sizeof(TeaContext));
}

#endif
