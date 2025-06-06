/**
 * @file m2354_crypto_hash.c
 * @brief M2354 hash hardware accelerator
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
#include "m2354.h"
#include "core/crypto.h"
#include "hardware/m2354/m2354_crypto.h"
#include "hardware/m2354/m2354_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (M2354_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief Update hash value
 * @param[in] opmode Hash algorithm
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in,out] h Intermediate hash value
 * @param[in] hLen Length of the intermediate hash value, in words
 **/

void hashProcessData(uint32_t opmode, const uint8_t *data,
   size_t length, uint32_t *h, size_t hLen)
{
   uint_t i;

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m2354CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Select the relevant hash algorithm
   CRPT->HMAC_CTL = CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk |
      CRPT_HMAC_CTL_DMACSCAD_Msk | opmode;

   //SHA-1, SHA-224, SHA-256 or SM3 algorithm?
   if(opmode == CRPT_HMAC_CTL_OPMODE_SHA1 || opmode == CRPT_HMAC_CTL_OPMODE_SHA224 ||
      opmode == CRPT_HMAC_CTL_OPMODE_SHA256 || opmode == CRPT_HMAC_CTL_SM3EN_Msk)
   {
      //Restore initial hash value
      for(i = 0; i < hLen; i++)
      {
         CRPT->HMAC_FDBCK[2 * i] = h[i];
      }
   }
   else
   {
      //Restore initial hash value
      for(i = 0; i < hLen; i++)
      {
         CRPT->HMAC_FDBCK[i] = h[i];
      }
   }

   //Start SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

   //Process input data
   for(i = 0; i < length; i += 4)
   {
      //Wait for the DATINREQ bit to be set
      while((CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk) == 0)
      {
      }

      //Write one word of data
      CRPT->HMAC_DATIN = __UNALIGNED_UINT32_READ(data + i);
   }

   //Wait for the processing to complete
   while((CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk) == 0)
   {
   }

   //SHA-1, SHA-224, SHA-256 or SM3 algorithm?
   if(opmode == CRPT_HMAC_CTL_OPMODE_SHA1 || opmode == CRPT_HMAC_CTL_OPMODE_SHA224 ||
      opmode == CRPT_HMAC_CTL_OPMODE_SHA256 || opmode == CRPT_HMAC_CTL_SM3EN_Msk)
   {
      //Save intermediate hash value
      for(i = 0; i < hLen; i++)
      {
         h[i] = CRPT->HMAC_FDBCK[2 * i];
      }
   }
   else
   {
      //Save intermediate hash value
      for(i = 0; i < hLen; i++)
      {
         h[i] = CRPT->HMAC_FDBCK[i];
      }
   }

   //Stop SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m2354CryptoMutex);
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
         hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA1, data, n, context->h,
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
            hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA1, context->buffer,
               context->size, context->h, SHA1_DIGEST_SIZE / 4);

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
   hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA1, context->buffer, 64,
      context->h, SHA1_DIGEST_SIZE / 4);
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
         hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA256, data, n, context->h,
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
            hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA256, context->buffer,
               context->size, context->h, SHA256_DIGEST_SIZE / 4);

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
   hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA256, context->buffer, 64,
      context->h, SHA256_DIGEST_SIZE / 4);
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
         hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA512, data, n,
            (uint32_t *) context->h, SHA512_DIGEST_SIZE / 4);

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
            hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA512, context->buffer,
               context->size, (uint32_t *) context->h, SHA512_DIGEST_SIZE / 4);

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
   hashProcessData(CRPT_HMAC_CTL_OPMODE_SHA512, context->buffer, 128,
      (uint32_t *) context->h, SHA512_DIGEST_SIZE / 4);
}

#endif
#if (SM3_SUPPORT == ENABLED)

/**
 * @brief Update the SM3 context with a portion of the message being hashed
 * @param[in] context Pointer to the SM3 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sm3Update(Sm3Context *context, const void *data, size_t length)
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
         hashProcessData(CRPT_HMAC_CTL_SM3EN_Msk, data, n, context->h,
            SM3_DIGEST_SIZE / 4);

         //Update the SM3 context
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

         //Update the SM3 context
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
            hashProcessData(CRPT_HMAC_CTL_SM3EN_Msk, context->buffer,
               context->size, context->h, SM3_DIGEST_SIZE / 4);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SM3 context
 **/

void sm3ProcessBlock(Sm3Context *context)
{
   //Update hash value
   hashProcessData(CRPT_HMAC_CTL_SM3EN_Msk, context->buffer, 64,
      context->h, SM3_DIGEST_SIZE / 4);
}

#endif
#endif
