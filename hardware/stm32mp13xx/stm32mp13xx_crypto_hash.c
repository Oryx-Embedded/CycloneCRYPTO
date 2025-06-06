/**
 * @file stm32mp13xx_crypto_hash.c
 * @brief STM32MP13 hash hardware accelerator
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
#include "stm32mp13xx.h"
#include "stm32mp13xx_hal.h"
#include "core/crypto.h"
#include "hardware/stm32mp13xx/stm32mp13xx_crypto.h"
#include "hardware/stm32mp13xx/stm32mp13xx_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "xof/keccak.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32MP13XX_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief HASH module initialization
 * @return Error code
 **/

error_t hashInit(void)
{
   //Enable HASH peripheral clock
   __HAL_RCC_HASH1_CLK_ENABLE();

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Update hash value
 * @param[in] algo Hash algorithm
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in,out] h Intermediate hash value
 * @param[in] hLen Length of the intermediate hash value, in words
 **/

void hashProcessData(uint32_t algo, const uint8_t *data, size_t length,
   uint32_t *h, size_t hLen)
{
   uint_t i;
   size_t blockSize;

   //Get block size
   if(algo == HASH_CR_ALGO_SHA1 || algo == HASH_CR_ALGO_SHA224 ||
      algo == HASH_CR_ALGO_SHA256)
   {
      blockSize = 64;
   }
   else
   {
      blockSize = 128;
   }

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32mp13xxCryptoMutex);

   //Select the relevant hash algorithm
   HASH1->CR = HASH_CR_DATATYPE_8B | algo;
   //Initialize the hash processor by setting the INIT bit
   HASH1->CR |= HASH_CR_INIT;

   //SHA-1, SHA-224 or SHA-256 algorithm?
   if(blockSize == 64)
   {
      //Restore initial hash value
      for(i = 0; i < hLen; i++)
      {
         HASH1->CSR[6 + i] = h[i];
         HASH1->CSR[14 + i] = h[i];
      }
   }
   else
   {
      //Restore initial hash value
      for(i = 0; i < hLen; i += 2)
      {
         HASH1->CSR[6 + i] = h[i + 1];
         HASH1->CSR[7 + i] = h[i];
         HASH1->CSR[39 + i / 2] = h[i];
         HASH1->CSR[47 + i / 2] = h[i + 1];
      }
   }

   //Input data are processed in a block-by-block fashion
   while(length >= blockSize)
   {
      //Write the first byte of the block
      HASH1->DIN = LOAD32LE(data);

      //Wait for the BUSY bit to be cleared
      while((HASH1->SR & HASH_SR_BUSY) != 0)
      {
      }

      //Write the rest of the block
      HASH1->DIN = LOAD32LE(data + 4);
      HASH1->DIN = LOAD32LE(data + 8);
      HASH1->DIN = LOAD32LE(data + 12);
      HASH1->DIN = LOAD32LE(data + 16);
      HASH1->DIN = LOAD32LE(data + 20);
      HASH1->DIN = LOAD32LE(data + 24);
      HASH1->DIN = LOAD32LE(data + 28);
      HASH1->DIN = LOAD32LE(data + 32);
      HASH1->DIN = LOAD32LE(data + 36);
      HASH1->DIN = LOAD32LE(data + 40);
      HASH1->DIN = LOAD32LE(data + 44);
      HASH1->DIN = LOAD32LE(data + 48);
      HASH1->DIN = LOAD32LE(data + 52);
      HASH1->DIN = LOAD32LE(data + 56);
      HASH1->DIN = LOAD32LE(data + 60);

      //128-octet data block?
      if(blockSize == 128)
      {
         HASH1->DIN = LOAD32LE(data + 64);
         HASH1->DIN = LOAD32LE(data + 68);
         HASH1->DIN = LOAD32LE(data + 72);
         HASH1->DIN = LOAD32LE(data + 76);
         HASH1->DIN = LOAD32LE(data + 80);
         HASH1->DIN = LOAD32LE(data + 84);
         HASH1->DIN = LOAD32LE(data + 88);
         HASH1->DIN = LOAD32LE(data + 92);
         HASH1->DIN = LOAD32LE(data + 96);
         HASH1->DIN = LOAD32LE(data + 100);
         HASH1->DIN = LOAD32LE(data + 104);
         HASH1->DIN = LOAD32LE(data + 108);
         HASH1->DIN = LOAD32LE(data + 112);
         HASH1->DIN = LOAD32LE(data + 116);
         HASH1->DIN = LOAD32LE(data + 120);
         HASH1->DIN = LOAD32LE(data + 124);
      }

      //Advance data pointer
      data += blockSize;
      length -= blockSize;
   }

   //Partial digest computation are triggered each time the application
   //writes the first word of the next block
   HASH1->DIN = 0;

   //Wait for the BUSY bit to be cleared
   while((HASH1->SR & HASH_SR_BUSY) != 0)
   {
   }

   //SHA-1, SHA-224 or SHA-256 algorithm?
   if(blockSize == 64)
   {
      //Save intermediate hash value
      for(i = 0; i < hLen; i++)
      {
         h[i] = HASH1->CSR[6 + i];
      }
   }
   else
   {
      //Save intermediate hash value
      for(i = 0; i < hLen; i += 2)
      {
         h[i] = HASH1->CSR[7 + i];
         h[i + 1] = HASH1->CSR[6 + i];
      }
   }

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32mp13xxCryptoMutex);
}


#if (SHA1_SUPPORT == ENABLED)

/**
 * @brief Update the SHA-1 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-1 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(HASH_CR_ALGO_SHA1, data, n, context->h,
            SHA1_DIGEST_SIZE / 4);

         //Update the SHA-1 context
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-1 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(HASH_CR_ALGO_SHA1, context->buffer, context->size,
               context->h, SHA1_DIGEST_SIZE / 4);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-1 context
 **/

void sha1ProcessBlock(Sha1Context *context)
{
   //Update hash value
   hashProcessData(HASH_CR_ALGO_SHA1, context->buffer, 64, context->h,
      SHA1_DIGEST_SIZE / 4);
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(HASH_CR_ALGO_SHA256, data, n, context->h,
            SHA256_DIGEST_SIZE / 4);

         //Update the SHA-256 context
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-256 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(HASH_CR_ALGO_SHA256, context->buffer, context->size,
               context->h, SHA256_DIGEST_SIZE / 4);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-256 context
 **/

void sha256ProcessBlock(Sha256Context *context)
{
   //Update hash value
   hashProcessData(HASH_CR_ALGO_SHA256, context->buffer, 64, context->h,
      SHA256_DIGEST_SIZE / 4);
}

#endif
#if (SHA512_SUPPORT == ENABLED)

/**
 * @brief Update the SHA-512 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-512 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha512Update(Sha512Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 128)
      {
         //The length must be a multiple of 128 bytes
         n = length - (length % 128);

         //Update hash value
         hashProcessData(HASH_CR_ALGO_SHA512, data, n, (uint32_t *) context->h,
            SHA512_DIGEST_SIZE / 4);

         //Update the SHA-512 context
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 128 bytes
         n = MIN(length, 128 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-512 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 128)
         {
            //Update hash value
            hashProcessData(HASH_CR_ALGO_SHA512, context->buffer, context->size,
               (uint32_t *) context->h, SHA512_DIGEST_SIZE / 4);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-512 context
 **/

void sha512ProcessBlock(Sha512Context *context)
{
   //Update hash value
   hashProcessData(HASH_CR_ALGO_SHA512, context->buffer, 128,
      (uint32_t *) context->h, SHA512_DIGEST_SIZE / 4);
}

#endif
#if (KECCAK_SUPPORT == ENABLED)

/**
 * @brief Update state array
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in] blockSize Block size
 * @param[in,out] a State array
 **/

void keccakProcessData(const uint8_t *data, size_t length, size_t blockSize,
   uint32_t *a)
{
   uint_t i;
   uint32_t algo;
   uint32_t temp;

   //Check block size
   if(blockSize == 72)
   {
      algo = HASH_CR_ALGO_SHA3_512;
   }
   else if(blockSize == 104)
   {
      algo = HASH_CR_ALGO_SHA3_384;
   }
   else if(blockSize == 136)
   {
      algo = HASH_CR_ALGO_SHA3_256;
   }
   else
   {
      algo = HASH_CR_ALGO_SHA3_224;
   }

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32mp13xxCryptoMutex);

   //Select the relevant hash algorithm
   HASH1->CR = HASH_CR_DATATYPE_8B | algo;
   //Initialize the hash processor by setting the INIT bit
   HASH1->CR |= HASH_CR_INIT;

   //Restore state array
   for(i = 0; i < 50; i++)
   {
      HASH1->CSR[6 + i] = HTOBE32(a[i]);
   }

   //Valid buffer?
   if(data != NULL)
   {
      //Input data are processed in a block-by-block fashion
      while(length >= blockSize)
      {
         //Write the first byte of the block
         HASH1->DIN = LOAD32LE(data);

         //Wait for the BUSY bit to be cleared
         while((HASH1->SR & HASH_SR_BUSY) != 0)
         {
         }

         //Write the rest of the block
         for(i = 4; i < blockSize; i += 4)
         {
            HASH1->DIN = LOAD32LE(data + i);
         }

         //Advance data pointer
         data += blockSize;
         length -= blockSize;
      }
   }
   else
   {
      //Input data are processed in a block-by-block fashion
      while(length >= blockSize)
      {
         //Write the first byte of the block
         HASH1->DIN = 0;

         //Wait for the BUSY bit to be cleared
         while((HASH1->SR & HASH_SR_BUSY) != 0)
         {
         }

         //Write the rest of the block
         for(i = 4; i < blockSize; i += 4)
         {
            HASH1->DIN = 0;
         }

         //Decrement length
         length -= blockSize;
      }
   }

   //Partial digest computation are triggered each time the application
   //writes the first word of the next block
   HASH1->DIN = 0;

   //Wait for the BUSY bit to be cleared
   while((HASH1->SR & HASH_SR_BUSY) != 0)
   {
   }

   //Save state array
   for(i = 0; i < 50; i++)
   {
      temp = HASH1->CSR[6 + i];
      a[i] = BETOH32(temp);
   }

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32mp13xxCryptoMutex);
}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the Keccak context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void keccakAbsorb(KeccakContext *context, const void *input, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->length == 0 && length >= context->blockSize)
      {
         //The length must be a multiple of the block size
         n = length - (length % context->blockSize);

         //Absorb the current block
         keccakProcessData(input, n, context->blockSize,
            (uint32_t *) context->a);

         //Advance the data pointer
         input = (uint8_t *) input + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most one block
         n = MIN(length, context->blockSize - context->length);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->length, input, n);
         //Update the length of the buffer
         context->length += n;

         //Advance the data pointer
         input = (uint8_t *) input + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->length == context->blockSize)
         {
            //Absorb the current block
            keccakProcessData(context->buffer, context->length,
               context->blockSize, (uint32_t *) context->a);

            //Empty the buffer
            context->length = 0;
         }
      }
   }
}


/**
 * @brief Block permutation
 * @param[in] context Pointer to the Keccak context
 **/

void keccakPermutBlock(KeccakContext *context)
{
   //Perform block permutation
   keccakProcessData(NULL, context->blockSize, context->blockSize,
      (uint32_t *) context->a);
}

#endif
#endif
