/**
 * @file mcxn547_crypto_hash.c
 * @brief NXP MCX N547 hash hardware accelerator
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
 * @version 2.5.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include <mcuxClEls.h>
#include "core/crypto.h"
#include "hardware/mcxn547/mcxn547_crypto.h"
#include "hardware/mcxn547/mcxn547_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MCXN547_CRYPTO_HASH_SUPPORT == ENABLED)

//Padding string
static const uint8_t padding[128] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/**
 * @brief Update hash value
 * @param[in] algo Hash algorithm
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in,out] h Intermediate hash value
 * @return Error code
 **/

error_t hashProcessData(uint32_t algo, const uint8_t *data, size_t length,
   uint32_t *h)
{
   error_t error;
   size_t blockSize;
   uint8_t temp[64];
   mcuxClEls_HashOption_t options;

   //Initialize status code
   error = NO_ERROR;

   //Get block size
   blockSize = (algo == MCUXCLELS_HASH_MODE_SHA_256) ? 64 : 128;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn547CryptoMutex);

   //Configure hash operation
   options.word.value = 0;
   options.bits.hashini = MCUXCLELS_HASH_INIT_ENABLE;
   options.bits.hashld = MCUXCLELS_HASH_LOAD_DISABLE;
   options.bits.hashmd = algo;
   options.bits.hashoe = MCUXCLELS_HASH_OUTPUT_ENABLE;
   options.bits.rtfupd = MCUXCLELS_HASH_RTF_UPDATE_DISABLE;
   options.bits.rtfoe = MCUXCLELS_HASH_RTF_OUTPUT_DISABLE;

   //Initialize hash computation
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Hash_Async(
      options, padding, blockSize, temp));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hash_Async) ||
      status != MCUXCLELS_STATUS_OK_WAIT)
   {
      error = ERROR_FAILURE;
   }

   //End of function call
   MCUX_CSSL_FP_FUNCTION_CALL_END();

   //Check status code
   if(!error)
   {
      //Wait for the operation to complete
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_WaitForOperation(
         MCUXCLELS_ERROR_FLAGS_CLEAR));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) ||
         status != MCUXCLELS_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Configure hash operation
      options.bits.hashini = MCUXCLELS_HASH_INIT_DISABLE;
      options.bits.hashld = MCUXCLELS_HASH_LOAD_ENABLE;

      //Update hash value
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Hash_Async(
         options, data, length, (uint8_t *) h));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hash_Async) ||
         status != MCUXCLELS_STATUS_OK_WAIT)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Wait for the operation to complete
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_WaitForOperation(
         MCUXCLELS_ERROR_FLAGS_CLEAR));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) ||
         status != MCUXCLELS_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn547CryptoMutex);

   //Return status code
   return error;
}


#if (SHA224_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-224 message digest context
 * @param[in] context Pointer to the SHA-224 context to initialize
 **/

void sha224Init(Sha224Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0xC1059ED8);
   context->h[1] = BETOH32(0x367CD507);
   context->h[2] = BETOH32(0x3070DD17);
   context->h[3] = BETOH32(0xF70E5939);
   context->h[4] = BETOH32(0xFFC00B31);
   context->h[5] = BETOH32(0x68581511);
   context->h[6] = BETOH32(0x64F98FA7);
   context->h[7] = BETOH32(0xBEFA4FA4);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

void sha256Init(Sha256Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0x6A09E667);
   context->h[1] = BETOH32(0xBB67AE85);
   context->h[2] = BETOH32(0x3C6EF372);
   context->h[3] = BETOH32(0xA54FF53A);
   context->h[4] = BETOH32(0x510E527F);
   context->h[5] = BETOH32(0x9B05688C);
   context->h[6] = BETOH32(0x1F83D9AB);
   context->h[7] = BETOH32(0x5BE0CD19);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

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
         hashProcessData(MCUXCLELS_HASH_MODE_SHA_256, data, n, context->h);

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
            hashProcessData(MCUXCLELS_HASH_MODE_SHA_256, context->buffer,
               context->size, context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest
 **/

void sha256Final(Sha256Context *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(context->size < 56)
   {
      paddingSize = 56 - context->size;
   }
   else
   {
      paddingSize = 64 + 56 - context->size;
   }

   //Append padding
   sha256Update(context, padding, paddingSize);

   //Append the length of the original message
   for(i = 0; i < 8; i++)
   {
      context->buffer[63 - i] = totalSize & 0xFF;
      totalSize >>= 8;
   }

   //Calculate the message digest
   hashProcessData(MCUXCLELS_HASH_MODE_SHA_256, context->buffer, 64,
      context->h);

   //Copy the resulting digest
   for(i = 0; i < (SHA256_DIGEST_SIZE / 4); i++)
   {
      STORE32LE(context->h[i], digest + i * 4);
   }
}


/**
 * @brief Finish the SHA-256 message digest (no padding added)
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest
 **/

void sha256FinalRaw(Sha256Context *context, uint8_t *digest)
{
   uint_t i;

   //Copy the resulting digest
   for(i = 0; i < (SHA256_DIGEST_SIZE / 4); i++)
   {
      STORE32LE(context->h[i], digest + i * 4);
   }
}

#endif
#if (SHA384_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-384 message digest context
 * @param[in] context Pointer to the SHA-384 context to initialize
 **/

void sha384Init(Sha384Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0xCBBB9D5DC1059ED8);
   context->h[1] = BETOH64(0x629A292A367CD507);
   context->h[2] = BETOH64(0x9159015A3070DD17);
   context->h[3] = BETOH64(0x152FECD8F70E5939);
   context->h[4] = BETOH64(0x67332667FFC00B31);
   context->h[5] = BETOH64(0x8EB44A8768581511);
   context->h[6] = BETOH64(0xDB0C2E0D64F98FA7);
   context->h[7] = BETOH64(0x47B5481DBEFA4FA4);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Finish the SHA-384 message digest (no padding added)
 * @param[in] context Pointer to the SHA-384 context
 * @param[out] digest Calculated digest
 **/

void sha384FinalRaw(Sha384Context *context, uint8_t *digest)
{
   uint_t i;

   //Copy the resulting digest
   for(i = 0; i < (SHA384_DIGEST_SIZE / 8); i++)
   {
      STORE64LE(context->h[i], digest + i * 8);
   }
}

#endif
#if (SHA512_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512 message digest context
 * @param[in] context Pointer to the SHA-512 context to initialize
 **/

void sha512Init(Sha512Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x6A09E667F3BCC908);
   context->h[1] = BETOH64(0xBB67AE8584CAA73B);
   context->h[2] = BETOH64(0x3C6EF372FE94F82B);
   context->h[3] = BETOH64(0xA54FF53A5F1D36F1);
   context->h[4] = BETOH64(0x510E527FADE682D1);
   context->h[5] = BETOH64(0x9B05688C2B3E6C1F);
   context->h[6] = BETOH64(0x1F83D9ABFB41BD6B);
   context->h[7] = BETOH64(0x5BE0CD19137E2179);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


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
         hashProcessData(MCUXCLELS_HASH_MODE_SHA_512, data, n,
            (uint32_t *) context->h);

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
            hashProcessData(MCUXCLELS_HASH_MODE_SHA_512, context->buffer,
               context->size, (uint32_t *) context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-512 message digest
 * @param[in] context Pointer to the SHA-512 context
 * @param[out] digest Calculated digest
 **/

void sha512Final(Sha512Context *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 112 modulo 128
   if(context->size < 112)
   {
      paddingSize = 112 - context->size;
   }
   else
   {
      paddingSize = 128 + 112 - context->size;
   }

   //Append padding
   sha512Update(context, padding, paddingSize);

   //Append the length of the original message
   for(i = 0; i < 16; i++)
   {
      context->buffer[127 - i] = totalSize & 0xFF;
      totalSize >>= 8;
   }

   //Calculate the message digest
   hashProcessData(MCUXCLELS_HASH_MODE_SHA_512, context->buffer, 128,
      (uint32_t *) context->h);

   //Copy the resulting digest
   for(i = 0; i < (SHA512_DIGEST_SIZE / 8); i++)
   {
      STORE64LE(context->h[i], digest + i * 8);
   }
}

#endif
#if (SHA512_224_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512/224 message digest context
 * @param[in] context Pointer to the SHA-512/224 context to initialize
 **/

void sha512_224Init(Sha512_224Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x8C3D37C819544DA2);
   context->h[1] = BETOH64(0x73E1996689DCD4D6);
   context->h[2] = BETOH64(0x1DFAB7AE32FF9C82);
   context->h[3] = BETOH64(0x679DD514582F9FCF);
   context->h[4] = BETOH64(0x0F6D2B697BD44DA8);
   context->h[5] = BETOH64(0x77E36F7304C48942);
   context->h[6] = BETOH64(0x3F9D85A86A1D36C8);
   context->h[7] = BETOH64(0x1112E6AD91D692A1);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

#endif
#if (SHA512_256_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512/256 message digest context
 * @param[in] context Pointer to the SHA-512/256 context to initialize
 **/

void sha512_256Init(Sha512_256Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x22312194FC2BF72C);
   context->h[1] = BETOH64(0x9F555FA3C84C64C2);
   context->h[2] = BETOH64(0x2393B86B6F53B151);
   context->h[3] = BETOH64(0x963877195940EABD);
   context->h[4] = BETOH64(0x96283EE2A88EFFE3);
   context->h[5] = BETOH64(0xBE5E1E2553863992);
   context->h[6] = BETOH64(0x2B0199FC2C85B8AA);
   context->h[7] = BETOH64(0x0EB72DDC81C52CA2);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

#endif
#endif
