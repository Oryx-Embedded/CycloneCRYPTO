/**
 * @file max32690_crypto_hash.c
 * @brief MAX32690 hash hardware accelerator
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
#include "mxc_device.h"
#include "mxc_sys.h"
#include "ctb.h"
#include "core/crypto.h"
#include "hardware/max32690/max32690_crypto.h"
#include "hardware/max32690/max32690_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MAX32690_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief Update hash value
 * @param[in] algo Hash algorithm
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in,out] h Intermediate hash value
 * @param[in] hLen Length of the intermediate hash value, in words
 **/

void hashProcessData(mxc_ctb_hash_func_t algo, const uint8_t *data,
   size_t length, uint32_t *h, size_t hLen)
{
   uint_t i;
   uint32_t temp;
   size_t blockSize;

   //Get block size
   if(algo == MXC_CTB_HASH_SHA1 || algo == MXC_CTB_HASH_SHA224 ||
      algo == MXC_CTB_HASH_SHA256)
   {
      blockSize = 64;
   }
   else
   {
      blockSize = 128;
   }

   //Acquire exclusive access to the CTB module
   osAcquireMutex(&max32690CryptoMutex);

   //Reset the engine by setting CTB_CTRL.rst
   MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

   //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
   //indicating the cryptographic accelerator is ready for use
   while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
   {
   }

   //Legacy support for the access behavior of the done flags
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;
   //Clear done flag
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_HSH_DONE;

   //Select the desired hash function
   MXC_CTB->hash_ctrl = (algo << MXC_F_CTB_HASH_CTRL_HASH_POS) &
      MXC_F_CTB_HASH_CTRL_HASH;

   //Set the length of the message in bytes
   MXC_CTB->hash_msg_sz[0] = length;
   MXC_CTB->hash_msg_sz[1] = 0;
   MXC_CTB->hash_msg_sz[2] = 0;
   MXC_CTB->hash_msg_sz[3] = 0;

   //Select hash function input source
   temp = MXC_CTB->ctrl & ~MXC_F_CTB_CTRL_SRC;
   temp |= MXC_CTB_HASH_SOURCE_INFIFO << MXC_F_CTB_CTRL_SRC_POS;
   MXC_CTB->ctrl = temp;

   //Initialize hash calculation
   MXC_CTB->hash_ctrl |= MXC_F_CTB_HASH_CTRL_INIT;

   //Wait for the initialization to complete
   while((MXC_CTB->hash_ctrl & MXC_F_CTB_HASH_CTRL_INIT) != 0)
   {
   }

   //SHA-1, SHA-224 or SHA-256 algorithm?
   if(blockSize == 64)
   {
      //Restore initial hash value
      for(i = 0; i < hLen; i++)
      {
         MXC_CTB->hash_digest[i] = htobe32(h[i]);
      }
   }
   else
   {
      //Restore initial hash value
      for(i = 0; i < hLen; i += 2)
      {
         MXC_CTB->hash_digest[i] = htobe32(h[i + 1]);
         MXC_CTB->hash_digest[i + 1] = htobe32(h[i]);
      }
   }

   //Input data are processed in a block-by-block fashion
   while(length >= blockSize)
   {
      //Write the block to be processed to the DIN registers
      MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data);
      MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 4);
      MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 8);
      MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 12);
      MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data + 16);
      MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 20);
      MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 24);
      MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 28);
      MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data + 32);
      MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 36);
      MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 40);
      MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 44);
      MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data + 48);
      MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 52);
      MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 56);
      MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 60);

      //128-octet data block?
      if(blockSize == 128)
      {
         MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data + 64);
         MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 68);
         MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 72);
         MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 76);
         MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data + 80);
         MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 84);
         MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 88);
         MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 92);
         MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data + 96);
         MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 100);
         MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 104);
         MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 108);
         MXC_CTB->din[0] = __UNALIGNED_UINT32_READ(data + 112);
         MXC_CTB->din[1] = __UNALIGNED_UINT32_READ(data + 116);
         MXC_CTB->din[2] = __UNALIGNED_UINT32_READ(data + 120);
         MXC_CTB->din[3] = __UNALIGNED_UINT32_READ(data + 124);
      }

      //Wait until the operation is complete
      while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_HSH_DONE) == 0)
      {
      }

      //Clear CTB_CTRL.hsh_done flag before starting the next hash operation
      MXC_CTB->ctrl |= MXC_F_CTB_CTRL_HSH_DONE;

      //Advance data pointer
      data += blockSize;
      length -= blockSize;
   }

   //SHA-1, SHA-224 or SHA-256 algorithm?
   if(blockSize == 64)
   {
      //Save intermediate hash value
      for(i = 0; i < hLen; i++)
      {
         h[i] = betoh32(MXC_CTB->hash_digest[i]);
      }
   }
   else
   {
      //Save intermediate hash value
      for(i = 0; i < hLen; i += 2)
      {
         h[i] = betoh32(MXC_CTB->hash_digest[i + 1]);
         h[i + 1] = betoh32(MXC_CTB->hash_digest[i]);
      }
   }

   //Disable hash engine
   MXC_CTB->hash_ctrl = (MXC_CTB_HASH_DIS << MXC_F_CTB_HASH_CTRL_HASH_POS) &
      MXC_F_CTB_HASH_CTRL_HASH;

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);
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
         hashProcessData(MXC_CTB_HASH_SHA1, data, n, context->h,
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
            hashProcessData(MXC_CTB_HASH_SHA1, context->buffer, context->size,
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
   hashProcessData(MXC_CTB_HASH_SHA1, context->buffer, 64, context->h,
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
         hashProcessData(MXC_CTB_HASH_SHA256, data, n, context->h,
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
            hashProcessData(MXC_CTB_HASH_SHA256, context->buffer, context->size,
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
   hashProcessData(MXC_CTB_HASH_SHA256, context->buffer, 64, context->h,
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
         hashProcessData(MXC_CTB_HASH_SHA512, data, n, (uint32_t *) context->h,
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
            hashProcessData(MXC_CTB_HASH_SHA512, context->buffer, context->size,
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
   hashProcessData(MXC_CTB_HASH_SHA512, context->buffer, 128,
      (uint32_t *) context->h, SHA512_DIGEST_SIZE / 4);
}

#endif
#endif
