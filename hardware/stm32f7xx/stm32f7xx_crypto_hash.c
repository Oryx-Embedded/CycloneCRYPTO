/**
 * @file stm32f7xx_crypto_hash.c
 * @brief STM32F7 hash hardware accelerator
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.1.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "stm32f7xx.h"
#include "stm32f7xx_hal.h"
#include "stm32f7xx_hal_hash.h"
#include "stm32f7xx_hal_hash_ex.h"
#include "core/crypto.h"
#include "hardware/stm32f7xx/stm32f7xx_crypto.h"
#include "hardware/stm32f7xx/stm32f7xx_crypto_hash.h"
#include "hash/md5.h"
#include "hash/sha1.h"
#include "hash/sha224.h"
#include "hash/sha256.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32F7XX_CRYPTO_HASH_SUPPORT == ENABLED)

//Global variable
static HASH_HandleTypeDef HASH_Handle;


/**
 * @brief HASH module initialization
 * @return Error code
 **/

error_t hashInit(void)
{
   HAL_StatusTypeDef status;

   //Enable HASH peripheral clock
   __HAL_RCC_HASH_CLK_ENABLE();

   //Reset HASH module
   status = HAL_HASH_DeInit(&HASH_Handle);

   //Check status code
   if(status == HAL_OK)
   {
      //Set parameters
      HASH_Handle.Init.DataType = HASH_DATATYPE_8B;

      //Initialize HASH module
      status = HAL_HASH_Init(&HASH_Handle);
   }

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Save hash context
 * @param[out] buffer Buffer where to store the hardware context
 **/

void hashSaveContext(uint32_t *buffer)
{
   //Save peripheral state
   buffer[0] = HASH_Handle.Phase;

   //Save hardware context
   HAL_HASH_ContextSaving(&HASH_Handle, (uint8_t *) &buffer[1]);
}


/**
 * @brief Restore hash context
 * @param[in] buffer Buffer containing the hardware context
 **/

void hashRestoreContext(uint32_t *buffer)
{
   //Restore hardware context
   HAL_HASH_Init(&HASH_Handle);
   HAL_HASH_ContextRestoring(&HASH_Handle, (uint8_t *) &buffer[1]);

   //Restore peripheral state
   HASH_Handle.Phase = (HAL_HASH_PhaseTypeDef) buffer[0];
}


/**
 * @brief Digest a message using MD5
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t md5Compute(const void *data, size_t length, uint8_t *digest)
{
   HAL_StatusTypeDef status;

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Digest the message
   status = HAL_HASH_MD5_Start(&HASH_Handle, (uint8_t *) data, length,
      digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize MD5 message digest context
 * @param[in] context Pointer to the MD5 context to initialize
 **/

void md5Init(Md5Context *context)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Number of bytes in the buffer
   context->size = 0;
}


/**
 * @brief Update the MD5 context with a portion of the message being hashed
 * @param[in] context Pointer to the MD5 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void md5Update(Md5Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 4)
      {
         //The length must be a multiple of 4 bytes
         n = length - (length % 4);

         //Update hash value
         HAL_HASH_MD5_Accmlt(&HASH_Handle, (uint8_t *) data, n);

         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 4 bytes
         n = MIN(length, 4 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the MD5 context
         context->size += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 4)
         {
            //Update hash value
            HAL_HASH_MD5_Accmlt(&HASH_Handle, context->buffer, 4);
            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);
}


/**
 * @brief Finish the MD5 message digest
 * @param[in] context Pointer to the MD5 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void md5Final(Md5Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Finalize hash computation
   HAL_HASH_MD5_Accmlt_End(&HASH_Handle, context->buffer, context->size,
      context->digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, MD5_DIGEST_SIZE);
   }
}


/**
 * @brief Finish the MD5 message digest (no padding added)
 * @param[in] context Pointer to the MD5 context
 * @param[out] digest Calculated digest
 **/

void md5FinalRaw(Md5Context *context, uint8_t *digest)
{
   uint_t i;
   uint32_t temp;
   uint8_t buffer[4];

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Force the current block to be processed by the hardware
   osMemset(buffer, 0, 4);
   HAL_HASH_MD5_Accmlt(&HASH_Handle, buffer, 4);

   //Wait for the processing to complete
   while((HASH->SR & HASH_SR_BUSY) != 0)
   {
   }

   //Get the intermediate hash value
   for(i = 0; i < MD5_DIGEST_SIZE / 4; i++)
   {
      temp = HASH->CSR[6 + i];
      STORE32BE(temp, digest + i * 4);
   }

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);
}


/**
 * @brief Digest a message using SHA-1
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha1Compute(const void *data, size_t length, uint8_t *digest)
{
   HAL_StatusTypeDef status;

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Digest the message
   status = HAL_HASH_SHA1_Start(&HASH_Handle, (uint8_t *) data, length,
      digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-1 message digest context
 * @param[in] context Pointer to the SHA-1 context to initialize
 **/

void sha1Init(Sha1Context *context)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Number of bytes in the buffer
   context->size = 0;
}


/**
 * @brief Update the SHA-1 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-1 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 4)
      {
         //The length must be a multiple of 4 bytes
         n = length - (length % 4);

         //Update hash value
         HAL_HASH_SHA1_Accmlt(&HASH_Handle, (uint8_t *) data, n);

         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 4 bytes
         n = MIN(length, 4 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-1 context
         context->size += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 4)
         {
            //Update hash value
            HAL_HASH_SHA1_Accmlt(&HASH_Handle, context->buffer, 4);
            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);
}


/**
 * @brief Finish the SHA-1 message digest
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha1Final(Sha1Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Finalize hash computation
   HAL_HASH_SHA1_Accmlt_End(&HASH_Handle, context->buffer, context->size,
      context->digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA1_DIGEST_SIZE);
   }
}


/**
 * @brief Finish the SHA-1 message digest (no padding added)
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest
 **/

void sha1FinalRaw(Sha1Context *context, uint8_t *digest)
{
   uint_t i;
   uint32_t temp;
   uint8_t buffer[4];

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Force the current block to be processed by the hardware
   osMemset(buffer, 0, 4);
   HAL_HASH_SHA1_Accmlt(&HASH_Handle, buffer, 4);

   //Wait for the processing to complete
   while((HASH->SR & HASH_SR_BUSY) != 0)
   {
   }

   //Get the intermediate hash value
   for(i = 0; i < SHA1_DIGEST_SIZE / 4; i++)
   {
      temp = HASH->CSR[6 + i];
      STORE32BE(temp, digest + i * 4);
   }

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);
}


/**
 * @brief Digest a message using SHA-224
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha224Compute(const void *data, size_t length, uint8_t *digest)
{
   HAL_StatusTypeDef status;

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Digest the message
   status = HAL_HASHEx_SHA224_Start(&HASH_Handle, (uint8_t *) data, length,
      digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-224 message digest context
 * @param[in] context Pointer to the SHA-224 context to initialize
 **/

void sha224Init(Sha224Context *context)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Number of bytes in the buffer
   context->size = 0;
}


/**
 * @brief Update the SHA-224 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-224 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha224Update(Sha224Context *context, const void *data, size_t length)
{
   size_t n;

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 4)
      {
         //The length must be a multiple of 4 bytes
         n = length - (length % 4);

         //Update hash value
         HAL_HASHEx_SHA224_Accmlt(&HASH_Handle, (uint8_t *) data, n);

         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 4 bytes
         n = MIN(length, 4 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-224 context
         context->size += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 4)
         {
            //Update hash value
            HAL_HASHEx_SHA224_Accmlt(&HASH_Handle, context->buffer, 4);
            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);
}


/**
 * @brief Finish the SHA-224 message digest
 * @param[in] context Pointer to the SHA-224 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha224Final(Sha224Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Finalize hash computation
   HAL_HASHEx_SHA224_Accmlt_End(&HASH_Handle, context->buffer, context->size,
      context->digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA224_DIGEST_SIZE);
   }
}


/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
   HAL_StatusTypeDef status;

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Digest the message
   status = HAL_HASHEx_SHA256_Start(&HASH_Handle, (uint8_t *) data, length,
      digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

void sha256Init(Sha256Context *context)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Initialize hash computation
   HAL_HASH_Init(&HASH_Handle);

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Number of bytes in the buffer
   context->size = 0;
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

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 4)
      {
         //The length must be a multiple of 4 bytes
         n = length - (length % 4);

         //Update hash value
         HAL_HASHEx_SHA256_Accmlt(&HASH_Handle, (uint8_t *) data, n);

         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 4 bytes
         n = MIN(length, 4 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-256 context
         context->size += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 4)
         {
            //Update hash value
            HAL_HASHEx_SHA256_Accmlt(&HASH_Handle, context->buffer, 4);
            //Empty the buffer
            context->size = 0;
         }
      }
   }

   //Save hash context
   hashSaveContext(context->hwContext);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha256Final(Sha256Context *context, uint8_t *digest)
{
   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Finalize hash computation
   HAL_HASHEx_SHA256_Accmlt_End(&HASH_Handle, context->buffer, context->size,
      context->digest, HAL_MAX_DELAY);

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA256_DIGEST_SIZE);
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
   uint32_t temp;
   uint8_t buffer[4];

   //Acquire exclusive access to the HASH module
   osAcquireMutex(&stm32f7xxCryptoMutex);

   //Restore hash context
   hashRestoreContext(context->hwContext);

   //Force the current block to be processed by the hardware
   osMemset(buffer, 0, 4);
   HAL_HASHEx_SHA256_Accmlt(&HASH_Handle, buffer, 4);

   //Wait for the processing to complete
   while((HASH->SR & HASH_SR_BUSY) != 0)
   {
   }

   //Get the intermediate hash value
   for(i = 0; i < SHA256_DIGEST_SIZE / 4; i++)
   {
      temp = HASH->CSR[6 + i];
      STORE32BE(temp, digest + i * 4);
   }

   //Release exclusive access to the HASH module
   osReleaseMutex(&stm32f7xxCryptoMutex);
}

#endif
