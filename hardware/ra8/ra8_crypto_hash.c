/**
 * @file ra8_crypto_hash.c
 * @brief RA8 hash hardware accelerator
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
#include "hw_sce_hash_private.h"
#include "core/crypto.h"
#include "hardware/ra8/ra8_crypto.h"
#include "hardware/ra8/ra8_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (RA8_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief Update hash value
 * @param[in] algo Hash algorithm
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in,out] h Hash value
 **/

void hashProcessData(uint32_t algo, const uint8_t *data, size_t length,
   uint32_t *h)
{
   uint32_t type;
   uint32_t command;
   uint32_t state[20];
   uint32_t digest[16];

   //Hash type
   type = htobe32(algo);
   //Command
   command = HTOBE32(SCE_OEM_CMD_HASH_RESUME_TO_SUSPEND);

   //Clear state
   osMemset(state, 0, sizeof(state));

   //Acquire exclusive access to the RSIP7 module
   osAcquireMutex(&ra8CryptoMutex);

   //Restore hash state
   if(algo == SCE_OEM_CMD_HASH_TYPE_SHA1)
   {
      state[0] = h[0];
      state[2] = h[1];
      state[4] = h[2];
      state[6] = h[3];
      state[14] = h[4];
      state[17] = HTOBE32(0x80000000);
      state[18] = HTOBE32(0x7F000000);
      state[19] = HTOBE32(0x00FEFFFF);
   }
   else if(algo == SCE_OEM_CMD_HASH_TYPE_SHA256)
   {
      state[0] = h[0];
      state[2] = h[1];
      state[4] = h[2];
      state[6] = h[3];
      state[8] = h[4];
      state[10] = h[5];
      state[12] = h[6];
      state[14] = h[7];
      state[17] = HTOBE32(0x80000000);
      state[18] = HTOBE32(0x7F000000);
      state[19] = HTOBE32(0x00FEFFFF);
   }
   else
   {
      state[0] = h[0];
      state[1] = h[1];
      state[2] = h[2];
      state[3] = h[3];
      state[4] = h[4];
      state[5] = h[5];
      state[6] = h[6];
      state[7] = h[7];
      state[8] = h[8];
      state[9] = h[9];
      state[10] = h[10];
      state[11] = h[11];
      state[12] = h[12];
      state[13] = h[13];
      state[14] = h[14];
      state[15] = h[15];
      state[17] = HTOBE32(0x80000000);
      state[18] = HTOBE32(0x7F000000);
      state[19] = HTOBE32(0x00FCFFFF);
   }

   //Accelerate inner compression loop
   HW_SCE_ShaGenerateMessageDigestSub(&type, &command, (uint32_t *) data, NULL,
      state, digest, state, length / 4);

   //Save intermediate hash value
   if(algo == SCE_OEM_CMD_HASH_TYPE_SHA1)
   {
      h[0] = state[0];
      h[1] = state[2];
      h[2] = state[4];
      h[3] = state[6];
      h[4] = state[14];
   }
   else if(algo == SCE_OEM_CMD_HASH_TYPE_SHA256)
   {
      h[0] = state[0];
      h[1] = state[2];
      h[2] = state[4];
      h[3] = state[6];
      h[4] = state[8];
      h[5] = state[10];
      h[6] = state[12];
      h[7] = state[14];
   }
   else
   {
      h[0] = state[0];
      h[1] = state[1];
      h[2] = state[2];
      h[3] = state[3];
      h[4] = state[4];
      h[5] = state[5];
      h[6] = state[6];
      h[7] = state[7];
      h[8] = state[8];
      h[9] = state[9];
      h[10] = state[10];
      h[11] = state[11];
      h[12] = state[12];
      h[13] = state[13];
      h[14] = state[14];
      h[15] = state[15];
   }

   //Release exclusive access to the RSIP7 module
   osReleaseMutex(&ra8CryptoMutex);
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
         hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA1, data, n, context->h);

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
            hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA1, context->buffer,
               context->size, context->h);

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
   hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA1, context->buffer, 64,
      context->h);
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
         hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA256, data, n, context->h);

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
            hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA256, context->buffer,
               context->size, context->h);

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
   hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA256, context->buffer, 64,
      context->h);
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
         hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA512, data, n,
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
            hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA512, context->buffer,
               context->size, (uint32_t *) context->h);

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
   hashProcessData(SCE_OEM_CMD_HASH_TYPE_SHA512, context->buffer, 128,
      (uint32_t *) context->h);
}

#endif
#endif
