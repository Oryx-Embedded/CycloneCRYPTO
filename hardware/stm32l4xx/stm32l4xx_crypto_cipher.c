/**
 * @file stm32l4xx_crypto_cipher.c
 * @brief STM32L4 cipher hardware accelerator
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
#include "stm32l4xx.h"
#include "stm32l4xx_hal.h"
#include "stm32l4xx_hal_cryp.h"
#include "core/crypto.h"
#include "hardware/stm32l4xx/stm32l4xx_crypto.h"
#include "hardware/stm32l4xx/stm32l4xx_crypto_cipher.h"
#include "cipher/aes.h"
#include "cipher_mode/ecb.h"
#include "cipher_mode/cbc.h"
#include "cipher_mode/ctr.h"
#include "aead/gcm.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32L4XX_CRYPTO_CIPHER_SUPPORT == ENABLED)

//Global variable
static CRYP_HandleTypeDef CRYP_Handle;


/**
 * @brief CRYP module initialization
 * @return Error code
 **/

error_t crypInit(void)
{
   HAL_StatusTypeDef status;

   //Enable AES peripheral clock
   __HAL_RCC_AES_CLK_ENABLE();

   //Set instance
   CRYP_Handle.Instance = AES;

   //Reset CRYP module
   status = HAL_CRYP_DeInit(&CRYP_Handle);

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Perform encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @return Error code
 **/

error_t crypProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length)
{
   HAL_StatusTypeDef status;

   //Initialize status code
   status = HAL_OK;

   //Set CRYP parameters
   CRYP_Handle.Instance = AES;
   CRYP_Handle.Init.DataType = CRYP_DATATYPE_8B;
   CRYP_Handle.Init.KeyWriteFlag = CRYP_KEY_WRITE_ENABLE;
   CRYP_Handle.Init.pKey = (uint8_t *) context->ek;
   CRYP_Handle.Init.pInitVect = iv;

   //Check the length of the key
   if(context->nr == 10)
   {
      //128-bit key
      CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_128B;
   }
   else if(context->nr == 14)
   {
      //256-bit key
      CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_256B;
   }
   else
   {
      //192-bit keys are not supported
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
      //Check whether input and output pointers are 32-bit aligned
      if(((uintptr_t) input & 3) == 0 && ((uintptr_t) output & 3) == 0)
      {
         //Perform encryption or decryption
         status = HAL_CRYPEx_AES(&CRYP_Handle, (uint8_t *) input, length,
            output, HAL_MAX_DELAY);
      }
      else
      {
         size_t i;
         size_t n;
         uint32_t buffer[16];

         //Process payload data
         for(i = 0; i < length && status == HAL_OK; i += n)
         {
            //Use an intermediate buffer to ensure proper alignment
            n = MIN(length - i, sizeof(buffer));

            //Copy input data
            osMemcpy(buffer, input + i, n);

            //Perform encryption or decryption
            status = HAL_CRYPEx_AES(&CRYP_Handle, (uint8_t *) buffer, n,
               (uint8_t *) buffer, HAL_MAX_DELAY);

            //Copy output data
            osMemcpy(output + i, buffer, n);
         }
      }
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Update the value of the initialization vector
      if(iv != NULL)
      {
         HAL_CRYPEx_Read_IVRegisters(&CRYP_Handle, iv);
      }
   }

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
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
   else if(keyLen == 32)
   {
      //14 rounds are required for 256-bit key
      context->nr = 14;
   }
   else
   {
      //192-bit keys are not supported
      return ERROR_INVALID_KEY_LENGTH;
   }

   //Determine the number of 32-bit words in the key
   keyLen /= 4;

   //Copy the original key
   for(i = 0; i < keyLen; i++)
   {
      context->ek[i] = LOAD32LE(key + (i * 4));
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
   osAcquireMutex(&stm32l4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
   CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_ECB;

   //Encrypt payload data
   crypProcessData(context, NULL, input, output, AES_BLOCK_SIZE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32l4xxCryptoMutex);
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
   osAcquireMutex(&stm32l4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_DECRYPT;
   CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_ECB;

   //Encrypt payload data
   crypProcessData(context, NULL, input, output, AES_BLOCK_SIZE);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32l4xxCryptoMutex);
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
         osAcquireMutex(&stm32l4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
         CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_ECB;

         //Encrypt payload data
         error = crypProcessData(context, NULL, p, c, length);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32l4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
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
         osAcquireMutex(&stm32l4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_KEYDERIVATION_DECRYPT;
         CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_ECB;

         //Decrypt payload data
         error = crypProcessData(context, NULL, c, p, length);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32l4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
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
         osAcquireMutex(&stm32l4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
         CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_CBC;

         //Encrypt payload data
         error = crypProcessData(context, iv, p, c, length);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32l4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
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
         osAcquireMutex(&stm32l4xxCryptoMutex);

         //Set operation mode
         CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_KEYDERIVATION_DECRYPT;
         CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_CBC;

         //Decrypt payload data
         error = crypProcessData(context, iv, c, p, length);

         //Release exclusive access to the CRYP module
         osReleaseMutex(&stm32l4xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
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
            osAcquireMutex(&stm32l4xxCryptoMutex);

            //Set operation mode
            CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
            CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_CTR;

            //Encrypt payload data
            error = crypProcessData(context, t, p, c, length);

            //Release exclusive access to the CRYP module
            osReleaseMutex(&stm32l4xxCryptoMutex);
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
 * @return Error code
 **/

error_t crypProcessAeadData(AesContext *context, const uint8_t *iv,
   const uint8_t *a, size_t aLen, const uint8_t *input, uint8_t *output,
   size_t length, uint8_t *t)
{
   HAL_StatusTypeDef status;
   size_t i;
   size_t n;
   uint32_t buffer[16];
   uint8_t initVect[16];

   //Initialize status code
   status = HAL_OK;

   //When the length of the IV is 96 bits, the padding string is appended to
   //the IV to form the pre-counter block
   osMemcpy(initVect, iv, 12);
   initVect[12] = 0;
   initVect[13] = 0;
   initVect[14] = 0;
   initVect[15] = 2;

   //Set CRYP parameters
   CRYP_Handle.Instance = AES;
   CRYP_Handle.Init.DataType = CRYP_DATATYPE_8B;
   CRYP_Handle.Init.ChainingMode = CRYP_CHAINMODE_AES_GCM_GMAC;
   CRYP_Handle.Init.KeyWriteFlag = CRYP_KEY_WRITE_ENABLE;
   CRYP_Handle.Init.GCMCMACPhase = CRYP_GCM_INIT_PHASE;
   CRYP_Handle.Init.pKey = (uint8_t *) context->ek;
   CRYP_Handle.Init.pInitVect = initVect;

   //Check the length of the additional data
   if(aLen > 0)
   {
      CRYP_Handle.Init.Header = (uint8_t *) a;
      CRYP_Handle.Init.HeaderSize = aLen;
   }
   else
   {
      CRYP_Handle.Init.Header = NULL;
      CRYP_Handle.Init.HeaderSize = 0;
   }

   //Check the length of the key
   if(context->nr == 10)
   {
      //128-bit key
      CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_128B;
   }
   else if(context->nr == 14)
   {
      //256-bit key
      CRYP_Handle.Init.KeySize = CRYP_KEYSIZE_256B;
   }
   else
   {
      //192-bit keys are not supported
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
      //Initialize GCM operation
      status = HAL_CRYPEx_AES_Auth(&CRYP_Handle, NULL, 0, NULL, HAL_MAX_DELAY);
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Update processing phase
      CRYP_Handle.Init.GCMCMACPhase = CRYP_GCMCMAC_HEADER_PHASE;

      //Process additional data
      status = HAL_CRYPEx_AES_Auth(&CRYP_Handle, NULL, 0, NULL, HAL_MAX_DELAY);
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Update processing phase
      CRYP_Handle.Init.GCMCMACPhase = CRYP_GCM_PAYLOAD_PHASE;

      //Check whether input and output pointers are 32-bit aligned
      if(((uintptr_t) input & 3) == 0 && ((uintptr_t) output & 3) == 0 &&
         length >= 16)
      {
         //Process complete blocks only
         n = length - (length % 16);

         //Perform encryption or decryption
         status = HAL_CRYPEx_AES_Auth(&CRYP_Handle, (uint8_t *) input, n,
            output, HAL_MAX_DELAY);
      }
      else
      {
         n = 0;
      }

      //Process the remaining blocks
      for(i = n; i < length && status == HAL_OK; i += n)
      {
         //Use an intermediate buffer to ensure proper alignment
         n = MIN(length - i, sizeof(buffer));

         //Copy input data
         osMemcpy(buffer, input + i, n);

         //Perform encryption or decryption
         status = HAL_CRYPEx_AES_Auth(&CRYP_Handle, (uint8_t *) buffer, n,
            (uint8_t *) buffer, HAL_MAX_DELAY);

         //Copy output data
         osMemcpy(output + i, buffer, n);
      }
   }

   //Check status code
   if(status == HAL_OK)
   {
      //Update processing phase
      CRYP_Handle.Init.GCMCMACPhase = CRYP_GCMCMAC_FINAL_PHASE;

      //Generate authentication tag
      status = HAL_CRYPEx_AES_Auth(&CRYP_Handle, NULL, length, t,
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
   AesContext *aesContext;

   //The CRYP module only supports AES cipher algorithm
   if(cipherAlgo != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Point to the AES context
   aesContext = (AesContext *) cipherContext;

   //The CRYP module only supports 128-bit and 256-bit keys
   if(aesContext->nr != 10 && aesContext->nr != 14)
      return ERROR_INVALID_KEY_LENGTH;

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

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32l4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;

   //Perform AEAD encryption
   error = crypProcessAeadData(context->cipherContext, iv, a, aLen, p, c,
      length, authTag);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32l4xxCryptoMutex);

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
   uint8_t authTag[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32l4xxCryptoMutex);

   //Set operation mode
   CRYP_Handle.Init.OperatingMode = CRYP_ALGOMODE_DECRYPT;

   //Perform AEAD decryption
   error = crypProcessAeadData(context->cipherContext, iv, a, aLen, c, p,
      length, authTag);

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32l4xxCryptoMutex);

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
