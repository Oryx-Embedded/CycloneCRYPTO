/**
 * @file stm32f4xx_crypto_cipher.c
 * @brief STM32F4 cipher hardware accelerator
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
#include "stm32f4xx.h"
#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_cryp.h"
#include "stm32f4xx_hal_cryp_ex.h"
#include "core/crypto.h"
#include "hardware/stm32f4xx/stm32f4xx_crypto.h"
#include "hardware/stm32f4xx/stm32f4xx_crypto_cipher.h"
#include "cipher/des.h"
#include "cipher/des3.h"
#include "cipher/aes.h"
#include "cipher_mode/ecb.h"
#include "cipher_mode/cbc.h"
#include "cipher_mode/ctr.h"
#include "aead/gcm.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32F4XX_CRYPTO_CIPHER_SUPPORT == ENABLED)

//Global variable
static CRYP_HandleTypeDef CRYP_Handle;


/**
 * @brief CRYP module initialization
 * @return Error code
 **/

error_t crypInit(void)
{
   HAL_StatusTypeDef status;

   //Enable CRYP peripheral clock
   __HAL_RCC_CRYP_CLK_ENABLE();

   //Set instance
   CRYP_Handle.Instance = CRYP;

   //Reset CRYP module
   status = HAL_CRYP_DeInit(&CRYP_Handle);

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Perform encryption or decryption
 * @param[in] context Cipher algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode (TRUE for encryption, FALSE for decryption)
 * @return Error code
 **/

error_t crypProcessData(void *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, bool_t mode)
{
   HAL_StatusTypeDef status;
   uint32_t initVect[4];

   //Initialize status code
   status = HAL_OK;

   //Check cipher algorithm?
   if(CRYP_Handle.Init.Algorithm == CRYP_DES_ECB ||
      CRYP_Handle.Init.Algorithm == CRYP_DES_CBC)
   {
      DesContext *desContext;

      //Point to the DES context
      desContext = (DesContext *) context;

      //Set key
      CRYP_Handle.Init.pKey = desContext->ks;

      //Valid initialization vector?
      if(iv != NULL)
      {
         //Set the 64-bit value of the initialization vector
         initVect[0] = LOAD32BE(iv);
         initVect[1] = LOAD32BE(iv + 4);
      }
   }
   else if(CRYP_Handle.Init.Algorithm == CRYP_TDES_ECB ||
      CRYP_Handle.Init.Algorithm == CRYP_TDES_CBC)
   {
      Des3Context *des3Context;

      //Point to the Triple DES context
      des3Context = (Des3Context *) context;

      //Set key
      CRYP_Handle.Init.pKey = des3Context->k1.ks;

      //Valid initialization vector?
      if(iv != NULL)
      {
         //Set the 64-bit value of the initialization vector
         initVect[0] = LOAD32BE(iv);
         initVect[1] = LOAD32BE(iv + 4);
      }
   }
   else if(CRYP_Handle.Init.Algorithm == CRYP_AES_ECB ||
      CRYP_Handle.Init.Algorithm == CRYP_AES_CBC ||
      CRYP_Handle.Init.Algorithm == CRYP_AES_CTR)
   {
      AesContext *aesContext;

      //Point to the AES context
      aesContext = (AesContext *) context;

      //Set key
      CRYP_Handle.Init.pKey = aesContext->ek;

      //Valid initialization vector?
      if(iv != NULL)
      {
         //Set the 128-bit value of the initialization vector
         initVect[0] = LOAD32BE(iv);
         initVect[1] = LOAD32BE(iv + 4);
         initVect[2] = LOAD32BE(iv + 8);
         initVect[3] = LOAD32BE(iv + 12);
      }

      //Check the length of the key
      if(aesContext->nr == 10)
      {
         //128-bit key
         CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_128B;
      }
      else if(aesContext->nr == 12)
      {
         //192-bit key
         CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_192B;
      }
      else if(aesContext->nr == 14)
      {
         //256-bit key
         CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_256B;
      }
      else
      {
         //Report an error
         status = HAL_ERROR;
      }
   }
   else
   {
      //Unknown cipher algorithm
      status = HAL_ERROR;
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Set CRYP parameters
      CRYP_Handle.Instance = CRYP;
      CRYP_Handle.Init.DataType = CRYP_DATATYPE_8B;
      CRYP_Handle.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
      CRYP_Handle.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;
      CRYP_Handle.Init.pInitVect = initVect;

      //Initialize CRYP module
      status = HAL_CRYP_Init(&CRYP_Handle);
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Perform encryption or decryption
      if(mode)
      {
         status = HAL_CRYP_Encrypt(&CRYP_Handle, (uint32_t *) input,
            length, (uint32_t *) output, HAL_MAX_DELAY);
      }
      else
      {
         status = HAL_CRYP_Decrypt(&CRYP_Handle, (uint32_t *) input,
            length, (uint32_t *) output, HAL_MAX_DELAY);
      }
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Valid initialization vector?
      if(iv != NULL)
      {
         //Update the value of the initialization vector
         initVect[0] = CRYP_Handle.Instance->IV0LR;
         STORE32BE(initVect[0], iv);
         initVect[1] = CRYP_Handle.Instance->IV0RR;
         STORE32BE(initVect[1], iv + 4);

         //128-bit initialization vector?
         if(CRYP_Handle.Init.Algorithm == CRYP_AES_ECB ||
            CRYP_Handle.Init.Algorithm == CRYP_AES_CBC ||
            CRYP_Handle.Init.Algorithm == CRYP_AES_CTR)
         {
            initVect[2] = CRYP_Handle.Instance->IV1LR;
            STORE32BE(initVect[2], iv + 8);
            initVect[3] = CRYP_Handle.Instance->IV1RR;
            STORE32BE(initVect[3], iv + 12);
         }
      }
   }

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize a DES context using the supplied key
 * @param[in] context Pointer to the DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key (must be set to 8)
 * @return Error code
 **/

error_t desInit(DesContext *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid key length?
   if(keyLen != 8)
      return ERROR_INVALID_KEY_LENGTH;

   //Copy the 64-bit key
   context->ks[0] = LOAD32BE(key + 0);
   context->ks[1] = LOAD32BE(key + 4);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void desEncryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.Algorithm = CRYP_DES_ECB;
   //Encrypt payload data
   crypProcessData(context, NULL, input, output, DES_BLOCK_SIZE, TRUE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);
}


/**
 * @brief Decrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void desDecryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.Algorithm = CRYP_DES_ECB;
   //Decrypt payload data
   crypProcessData(context, NULL, input, output, DES_BLOCK_SIZE, FALSE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);
}


/**
 * @brief Initialize a Triple DES context using the supplied key
 * @param[in] context Pointer to the Triple DES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t des3Init(Des3Context *context, const uint8_t *key, size_t keyLen)
{
   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check key length
   if(keyLen == 8)
   {
      //This option provides backward compatibility with DES, because the
      //first and second DES operations cancel out
      context->k1.ks[0] = LOAD32BE(key + 0);
      context->k1.ks[1] = LOAD32BE(key + 4);
      context->k1.ks[2] = LOAD32BE(key + 0);
      context->k1.ks[3] = LOAD32BE(key + 4);
      context->k1.ks[4] = LOAD32BE(key + 0);
      context->k1.ks[5] = LOAD32BE(key + 4);
   }
   else if(keyLen == 16)
   {
      //If the key length is 128 bits including parity, the first 8 bytes of the
      //encoding represent the key used for the two outer DES operations, and
      //the second 8 bytes represent the key used for the inner DES operation
      context->k1.ks[0] = LOAD32BE(key + 0);
      context->k1.ks[1] = LOAD32BE(key + 4);
      context->k1.ks[2] = LOAD32BE(key + 8);
      context->k1.ks[3] = LOAD32BE(key + 12);
      context->k1.ks[4] = LOAD32BE(key + 0);
      context->k1.ks[5] = LOAD32BE(key + 4);
   }
   else if(keyLen == 24)
   {
      //If the key length is 192 bits including parity, then 3 independent DES
      //keys are represented, in the order in which they are used for encryption
      context->k1.ks[0] = LOAD32BE(key + 0);
      context->k1.ks[1] = LOAD32BE(key + 4);
      context->k1.ks[2] = LOAD32BE(key + 8);
      context->k1.ks[3] = LOAD32BE(key + 12);
      context->k1.ks[4] = LOAD32BE(key + 16);
      context->k1.ks[5] = LOAD32BE(key + 20);
   }
   else
   {
      //The length of the key is not valid
      return ERROR_INVALID_KEY_LENGTH;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void des3EncryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.Algorithm = CRYP_TDES_ECB;
   //Encrypt payload data
   crypProcessData(context, NULL, input, output, DES3_BLOCK_SIZE, TRUE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void des3DecryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.Algorithm = CRYP_TDES_ECB;
   //Decrypt payload data
   crypProcessData(context, NULL, input, output, DES3_BLOCK_SIZE, FALSE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);
}


/**
 * @brief Key expansion
 * @param[in] context Pointer to the AES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen)
{
   size_t i;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the key
   if(keyLen == 16)
   {
      //10 rounds are required for 128-bit key
      context->nr = 10;
   }
   else if(keyLen == 24)
   {
      //12 rounds are required for 192-bit key
      context->nr = 12;
   }
   else if(keyLen == 32)
   {
      //14 rounds are required for 256-bit key
      context->nr = 14;
   }
   else
   {
      //Report an error
      return ERROR_INVALID_KEY_LENGTH;
   }

   //Determine the number of 32-bit words in the key
   keyLen /= 4;

   //Copy the original key
   for(i = 0; i < keyLen; i++)
   {
      context->ek[i] = LOAD32BE(key + (i * 4));
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.Algorithm = CRYP_AES_ECB;
   //Encrypt payload data
   crypProcessData(context, NULL, input, output, AES_BLOCK_SIZE, TRUE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.Algorithm = CRYP_AES_ECB;
   //Decrypt payload data
   crypProcessData(context, NULL, input, output, AES_BLOCK_SIZE, FALSE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);
}


/**
 * @brief ECB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ecbEncrypt(const CipherAlgo *cipher, void *context,
   const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_DES_ECB;
         //Encrypt payload data
         error = crypProcessData(context, NULL, p, c, length, TRUE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_TDES_ECB;
         //Encrypt payload data
         error = crypProcessData(context, NULL, p, c, length, TRUE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_AES_ECB;
         //Encrypt payload data
         error = crypProcessData(context, NULL, p, c, length, TRUE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //ECB mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Encrypt current block
         cipher->encryptBlock(context, p, c);

         //Next block
         p += cipher->blockSize;
         c += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief ECB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t ecbDecrypt(const CipherAlgo *cipher, void *context,
   const uint8_t *c, uint8_t *p, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_DES_ECB;
         //Decrypt payload data
         error = crypProcessData(context, NULL, c, p, length, FALSE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_TDES_ECB;
         //Decrypt payload data
         error = crypProcessData(context, NULL, c, p, length, FALSE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_AES_ECB;
         //Decrypt payload data
         error = crypProcessData(context, NULL, c, p, length, FALSE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //ECB mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Decrypt current block
         cipher->decryptBlock(context, c, p);

         //Next block
         c += cipher->blockSize;
         p += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief CBC encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t cbcEncrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_DES_CBC;
         //Encrypt payload data
         error = crypProcessData(context, iv, p, c, length, TRUE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_TDES_CBC;
         //Encrypt payload data
         error = crypProcessData(context, iv, p, c, length, TRUE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_AES_CBC;
         //Encrypt payload data
         error = crypProcessData(context, iv, p, c, length, TRUE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      size_t i;

      //CBC mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //XOR input block with IV contents
         for(i = 0; i < cipher->blockSize; i++)
         {
            c[i] = p[i] ^ iv[i];
         }

         //Encrypt the current block based upon the output of the previous
         //encryption
         cipher->encryptBlock(context, c, c);

         //Update IV with output block contents
         osMemcpy(iv, c, cipher->blockSize);

         //Next block
         p += cipher->blockSize;
         c += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief CBC decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t cbcDecrypt(const CipherAlgo *cipher, void *context,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_DES_CBC;
         //Decrypt payload data
         error = crypProcessData(context, iv, c, p, length, FALSE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % DES3_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_TDES_CBC;
         //Decrypt payload data
         error = crypProcessData(context, iv, c, p, length, FALSE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the length of the payload
      if(length == 0)
      {
         //No data to process
      }
      else if((length % AES_BLOCK_SIZE) == 0)
      {
         //Acquire exclusive access to the CRYP module
         osAcquireMutex(&stm32f4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.Algorithm = CRYP_AES_CBC;
         //Decrypt payload data
         error = crypProcessData(context, iv, c, p, length, FALSE);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32f4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      size_t i;
      uint8_t t[16];

      //CBC mode operates in a block-by-block fashion
      while(length >= cipher->blockSize)
      {
         //Save input block
         osMemcpy(t, c, cipher->blockSize);

         //Decrypt the current block
         cipher->decryptBlock(context, c, p);

         //XOR output block with IV contents
         for(i = 0; i < cipher->blockSize; i++)
         {
            p[i] ^= iv[i];
         }

         //Update IV with input block contents
         osMemcpy(iv, t, cipher->blockSize);

         //Next block
         c += cipher->blockSize;
         p += cipher->blockSize;
         length -= cipher->blockSize;
      }

      //The length of the payload must be a multiple of the block size
      if(length != 0)
      {
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief CTR encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] m Size in bits of the specific part of the block to be incremented
 * @param[in,out] t Initial counter block
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ctrEncrypt(const CipherAlgo *cipher, void *context, uint_t m,
   uint8_t *t, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(m == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length == 0)
         {
            //No data to process
         }
         else if((length % AES_BLOCK_SIZE) == 0)
         {
            //Acquire exclusive access to the CRYP module
            osAcquireMutex(&stm32f4xxCryptoMutex);

            //Set operation mode
            CRYP_Handle.Init.Algorithm = CRYP_AES_CTR;
            //Encrypt payload data
            error = crypProcessData(context, t, p, c, length, TRUE);

            //Release exclusive access to the CRYP module
            osReleaseMutex(&stm32f4xxCryptoMutex);
         }
         else
         {
            //The length of the payload must be a multiple of the block size
            error = ERROR_INVALID_LENGTH;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //Check the value of the parameter
      if((m % 8) == 0 && m <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint16_t temp;
         uint8_t o[16];

         //Determine the size, in bytes, of the specific part of the block
         //to be incremented
         m = m / 8;

         //Process plaintext
         while(length > 0)
         {
            //CTR mode operates in a block-by-block fashion
            n = MIN(length, cipher->blockSize);

            //Compute O(j) = CIPH(T(j))
            cipher->encryptBlock(context, t, o);

            //Compute C(j) = P(j) XOR T(j)
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Standard incrementing function
            for(temp = 1, i = 1; i <= m; i++)
            {
               //Increment the current byte and propagate the carry
               temp += t[cipher->blockSize - i];
               t[cipher->blockSize - i] = temp & 0xFF;
               temp >>= 8;
            }

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
      {
         //The value of the parameter is not valid
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}


#if defined(CRYP_CR_ALGOMODE_AES_GCM)

/**
 * @brief Perform AEAD encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] iv Initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[out] t Authentication tag
 * @param[in] mode Operation mode (TRUE for encryption, FALSE for decryption)
 * @return Error code
 **/

error_t crypProcessAeadData(AesContext *context, const uint8_t *iv,
   const uint8_t *a, size_t aLen, const uint8_t *input, uint8_t *output,
   size_t length, uint8_t *t, bool_t mode)
{
   HAL_StatusTypeDef status;
   uint32_t header[8];
   uint32_t initVect[4];

   //Initialize status code
   status = HAL_OK;

   //When the length of the IV is 96 bits, the padding string is appended to
   //the IV to form the pre-counter block
   initVect[0] = LOAD32BE(iv);
   initVect[1] = LOAD32BE(iv + 4);
   initVect[2] = LOAD32BE(iv + 8);
   initVect[3] = 2;

   //Pad additional data if necessary (workaround)
   osMemset(header, 0x00, sizeof(header));
   osMemcpy(header, a, aLen);

   //Set CRYP parameters
   CRYP_Handle.Instance = CRYP;
   CRYP_Handle.Init.DataType = CRYP_DATATYPE_8B;
   CRYP_Handle.Init.Algorithm = CRYP_AES_GCM;
   CRYP_Handle.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
   CRYP_Handle.Init.HeaderWidthUnit = CRYP_DATAWIDTHUNIT_WORD;
   CRYP_Handle.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;
   CRYP_Handle.Init.pKey = context->ek;
   CRYP_Handle.Init.pInitVect = initVect;
   CRYP_Handle.Init.Header = header;
   CRYP_Handle.Init.HeaderSize = (aLen + 3) / 4;

   //Check the length of the key
   if(context->nr == 10)
   {
      //128-bit key
      CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_128B;
   }
   else if(context->nr == 12)
   {
      //192-bit key
      CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_192B;
   }
   else if(context->nr == 14)
   {
      //256-bit key
      CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_256B;
   }
   else
   {
      //Report an error
      status = HAL_ERROR;
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Initialize CRYP module
      status = HAL_CRYP_Init(&CRYP_Handle);
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Process payload data
      if(mode)
      {
         status = HAL_CRYP_Encrypt(&CRYP_Handle, (uint32_t *) input,
            length, (uint32_t *) output, HAL_MAX_DELAY);
      }
      else
      {
         status = HAL_CRYP_Decrypt(&CRYP_Handle, (uint32_t *) input,
            length, (uint32_t *) output, HAL_MAX_DELAY);
      }
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Specify the length of the additional data, in bytes
      CRYP_Handle.Init.HeaderWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
      CRYP_Handle.Init.HeaderSize = aLen;

      //Generate the authentication tag
      status = HAL_CRYPEx_AESGCM_GenerateAuthTAG(&CRYP_Handle, (uint32_t *) t,
         HAL_MAX_DELAY);
   }

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize GCM context
 * @param[in] context Pointer to the GCM context
 * @param[in] cipherAlgo Cipher algorithm
 * @param[in] cipherContext Pointer to the cipher algorithm context
 * @return Error code
 **/

error_t gcmInit(GcmContext *context, const CipherAlgo *cipherAlgo,
   void *cipherContext)
{
   //The CRYP module only supports AES cipher algorithm
   if(cipherAlgo != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Save cipher algorithm context
   context->cipherAlgo = cipherAlgo;
   context->cipherContext = cipherContext;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Authenticated encryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmEncrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *p,
   uint8_t *c, size_t length, uint8_t *t, size_t tLen)
{
   error_t error;
   uint8_t authTag[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the additional data
   if(aLen > 32)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Pad input data if necessary (workaround)
   osMemset(t, 0, tLen);

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Perform AEAD encryption
   error = crypProcessAeadData(context->cipherContext, iv, a, aLen, p, c,
      length, authTag, TRUE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);

   //Check status code
   if(error == NO_ERROR)
   {
      //Copy the resulting authentication tag
      osMemcpy(t, authTag, tLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Authenticated decryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmDecrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *c,
   uint8_t *p, size_t length, const uint8_t *t, size_t tLen)
{
   error_t error;
   size_t i;
   uint8_t mask;
   uint8_t temp[16];
   uint8_t authTag[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the additional data
   if(aLen > 32)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Pad input data if necessary (workaround)
   osMemcpy(temp, t, tLen);
   osMemset((uint8_t *) t, 0, tLen);

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32f4xxCryptoMutex);

   //Perform AEAD decryption
   error = crypProcessAeadData(context->cipherContext, iv, a, aLen, c, p,
      length, authTag, FALSE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32f4xxCryptoMutex);

   //Restore authentication tag (workaround)
   osMemcpy((uint8_t *) t, temp, tLen);

   //Check status code
   if(error == NO_ERROR)
   {
      //The calculated tag is bitwise compared to the received tag
      for(mask = 0, i = 0; i < tLen; i++)
      {
         mask |= authTag[i] ^ t[i];
      }

      //The message is authenticated if and only if the tags match
      if(mask != 0)
      {
         error = ERROR_FAILURE;
      }
   }

   //Return status code
   return error;
}

#endif
#endif
