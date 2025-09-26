/**
 * @file mcxn547_crypto_cipher.c
 * @brief NXP MCX N547 cipher hardware accelerator
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
#include "hardware/mcxn547/mcxn547_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MCXN547_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Perform AES encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] algo Cipher algorithm
 * @param[in] mode Operation mode
 * @return Error code
 **/

error_t aesProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t algo, uint32_t mode)
{
   error_t error;
   size_t keyLen;
   mcuxClEls_CipherOption_t options;

   //Initialize status code
   error = NO_ERROR;

   //Check the length of the key
   if(context->nr == 10)
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_128;
   }
   else if(context->nr == 12)
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_192;
   }
   else
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_256;
   }

   //Configure cipher mode
   options.word.value = 0;
   options.bits.dcrpt = mode;
   options.bits.cphmde = algo;
   options.bits.extkey = MCUXCLELS_CIPHER_EXTERNAL_KEY;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn547CryptoMutex);

   //Perform AES encryption/decryption
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Cipher_Async(
      options, 0, (uint8_t *) context->ek, keyLen, input, length, iv, output));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) ||
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

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn547CryptoMutex);

   //Return status code
   return error;
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

   //Copy the key
   osMemcpy(context->ek, key, keyLen);

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
   //Perform AES encryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE,
      MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_ENCRYPT);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform AES encryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE,
      MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_DECRYPT);
}


#if (ECB_SUPPORT == ENABLED)

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
         //Encrypt payload data
         error = aesProcessData(context, NULL, p, c, length,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_ENCRYPT);
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
         //Decrypt payload data
         error = aesProcessData(context, NULL, c, p, length,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_DECRYPT);
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

#endif
#if (CBC_SUPPORT == ENABLED)

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
         //Encrypt payload data
         error = aesProcessData(context, iv, p, c, length,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC, MCUXCLELS_CIPHER_ENCRYPT);
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
         //Decrypt payload data
         error = aesProcessData(context, iv, c, p, length,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC, MCUXCLELS_CIPHER_DECRYPT);
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

#endif
#if (CTR_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

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

   //Check the value of the parameter
   if((m % 8) == 0 && m <= (cipher->blockSize * 8))
   {
      //Determine the size, in bytes, of the specific part of the block
      //to be incremented
      m = m / 8;

      //AES cipher algorithm?
      if(cipher == AES_CIPHER_ALGO)
      {
         size_t k;
         size_t n;

         //Process plaintext
         while(length > 0 && !error)
         {
            //Limit the number of blocks to process at a time
            k = 256 - t[AES_BLOCK_SIZE - 1];
            n = MIN(length, k * AES_BLOCK_SIZE);
            k = (n + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

            //Encrypt payload data
            error = aesProcessData(context, t, p, c, n,
               MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR,
               MCUXCLELS_CIPHER_ENCRYPT);

            //Standard incrementing function
            ctrIncBlock(t, k, AES_BLOCK_SIZE, m);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
      {
         size_t i;
         size_t n;
         uint8_t o[16];

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
            ctrIncBlock(t, 1, cipher->blockSize, m);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
   }
   else
   {
      //The value of the parameter is not valid
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}

#endif
#if (GCM_SUPPORT == ENABLED)

/**
 * @brief Perform AES-GCM encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] iv Initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[out] t Authentication tag
 * @param[in] mode Operation mode
 * @return Error code
 **/

error_t gcmProcessData(AesContext *context, const uint8_t *iv,
   const uint8_t *a, size_t aLen, const uint8_t *input, uint8_t *output,
   size_t length, uint8_t *t, uint32_t mode)
{
   error_t error;
   size_t i;
   size_t n;
   size_t keyLen;
   mcuxClEls_AeadOption_t options;
   uint8_t block[AES_BLOCK_SIZE];
   uint8_t aeadContext[MCUXCLELS_AEAD_CONTEXT_SIZE];

   //Initialize status code
   error = NO_ERROR;

   //Check the length of the key
   if(context->nr == 10)
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_128;
   }
   else if(context->nr == 12)
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_192;
   }
   else
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_256;
   }

   //Configure cipher mode
   options.word.value = 0;
   options.bits.dcrpt = mode;
   options.bits.extkey = MCUXCLELS_CIPHER_EXTERNAL_KEY;

   //Set initialization vector
   osMemcpy(block, iv, 12);
   block[12] = 0;
   block[13] = 0;
   block[14] = 0;
   block[15] = 1;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn547CryptoMutex);

   //Initialize GCM encryption/decryption
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Aead_Init_Async(
      options, 0, (uint8_t *) context->ek, keyLen, block, AES_BLOCK_SIZE,
      aeadContext));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Init_Async) ||
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

   //Process additional authenticated data
   for(i = 0; i < aLen && !error; i += n)
   {
      //Last block?
      if((aLen - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         n = aLen - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, a + i, n);

         //Process data
         MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Aead_UpdateAad_Async(
            options, 0, (uint8_t *) context->ek, keyLen, block, AES_BLOCK_SIZE,
            aeadContext));

         //Check the protection token and the return value
         if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateAad_Async) ||
            status != MCUXCLELS_STATUS_OK_WAIT)
         {
            error = ERROR_FAILURE;
         }

         //End of function call
         MCUX_CSSL_FP_FUNCTION_CALL_END();
      }
      else
      {
         //Process complete blocks only
         n = aLen - (aLen % AES_BLOCK_SIZE);

         //Process data
         MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Aead_UpdateAad_Async(
            options, 0, (uint8_t *) context->ek, keyLen, a, n, aeadContext));

         //Check the protection token and the return value
         if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateAad_Async) ||
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
   }

   //Process payload data
   for(i = 0; i < length && !error; i += n)
   {
      //Last block?
      if((length - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         n = length - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, input + i, n);

         //Specify the number of bytes in the last block
         options.bits.msgendw = n;

         //Process data
         MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Aead_UpdateData_Async(
            options, 0, (uint8_t *) context->ek, keyLen, block, AES_BLOCK_SIZE,
            block, aeadContext));

         //Check the protection token and the return value
         if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateData_Async) ||
            status != MCUXCLELS_STATUS_OK_WAIT)
         {
            error = ERROR_FAILURE;
         }

         //End of function call
         MCUX_CSSL_FP_FUNCTION_CALL_END();
      }
      else
      {
         //Process complete blocks only
         n = length - (length % AES_BLOCK_SIZE);

         //Process data
         MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Aead_UpdateData_Async(
            options, 0, (uint8_t *) context->ek, keyLen, input, n, output,
            aeadContext));

         //Check the protection token and the return value
         if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateData_Async) ||
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

      //Check status code
      if(!error)
      {
         //Last block?
         if((length - i) < AES_BLOCK_SIZE)
         {
            //Copy the partial block
            osMemcpy(output + i, block, n);
         }
      }
   }

   //Check status code
   if(!error)
   {
      //Finalize GCM encryption/decryption
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Aead_Finalize_Async(
         options, 0, (uint8_t *) context->ek, keyLen, aLen, length, t,
         aeadContext));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Finalize_Async) ||
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
   //Check parameters
   if(context == NULL || cipherContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //The ELS module only supports AES cipher algorithm
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

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Perform AES-GCM encryption
   error = gcmProcessData(context->cipherContext, iv, a, aLen, p, c, length,
      authTag, MCUXCLELS_AEAD_ENCRYPT);

   //Check status code
   if(!error)
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

   //Perform AES-GCM decryption
   error = gcmProcessData(context->cipherContext, iv, a, aLen, c, p, length,
      authTag, MCUXCLELS_AEAD_DECRYPT);

   //Check status code
   if(!error)
   {
      //The calculated tag is bitwise compared to the received tag
      for(mask = 0, i = 0; i < tLen; i++)
      {
         mask |= authTag[i] ^ t[i];
      }

      //The message is authenticated if and only if the tags match
      error = (mask == 0) ? NO_ERROR : ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
#if (CCM_SUPPORT == ENABLED)

/**
 * @brief Update CCM authentication tag
 * @param[in] context AES algorithm context
 * @param[in] input Data to be processed
 * @param[in] length Total number of data bytes to be processed
 * @param[in,out] t Authentication tag
 * @return Error code
 **/

error_t ccmProcessData(AesContext *context, const uint8_t *input, size_t length,
   uint8_t *t)
{
   error_t error;
   size_t keyLen;
   mcuxClEls_CmacOption_t cmacOptions;

   //Initialize status code
   error = NO_ERROR;

   //Check the length of the key
   if(context->nr == 10)
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_128;
   }
   else if(context->nr == 12)
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_192;
   }
   else
   {
      keyLen = MCUXCLELS_CIPHER_KEY_SIZE_AES_256;
   }

   //Configure CMAC operation
   cmacOptions.word.value = 0;
   cmacOptions.bits.initialize = MCUXCLELS_CMAC_INITIALIZE_DISABLE;
   cmacOptions.bits.finalize = MCUXCLELS_CMAC_FINALIZE_DISABLE;
   cmacOptions.bits.extkey = MCUXCLELS_CMAC_EXTERNAL_KEY_ENABLE;

   //Perform CMAC operation
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Cmac_Async(
      cmacOptions, 0, (uint8_t *) context->ek, keyLen, input, length, t));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) ||
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

   //Return status code
   return error;
}


/**
 * @brief Authenticated encryption using CCM
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t MAC resulting from the encryption process
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t ccmEncrypt(const CipherAlgo *cipher, void *context, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c,
   size_t length, uint8_t *t, size_t tLen)
{
   error_t error;
   size_t i;
   size_t j;
   size_t m;
   uint8_t ctr[AES_BLOCK_SIZE];
   uint8_t block[AES_BLOCK_SIZE];
   uint8_t authTag[AES_BLOCK_SIZE];

   //The ELS module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Make sure the cipher context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format first block B(0)
   error = ccmFormatBlock0(length, n, nLen, aLen, tLen, block);
   //Invalid parameters?
   if(error)
      return error;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn547CryptoMutex);

   //Calculate CIPH(B0)
   error = aesProcessData(context, NULL, block, authTag, AES_BLOCK_SIZE,
      MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_ENCRYPT);

   //Check status code
   if(!error)
   {
      //Any additional data?
      if(aLen > 0)
      {
         //Format the associated data
         osMemset(block, 0, 16);

         //Check the length of the associated data string
         if(aLen < 0xFF00)
         {
            //The length is encoded as 2 octets
            STORE16BE(aLen, block);

            //Number of bytes to copy
            m = MIN(aLen, 16 - 2);
            //Concatenate the associated data A
            osMemcpy(block + 2, a, m);
         }
         else
         {
            //The length is encoded as 6 octets
            block[0] = 0xFF;
            block[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aLen, block + 2);

            //Number of bytes to copy
            m = MIN(aLen, 16 - 6);
            //Concatenate the associated data A
            osMemcpy(block + 6, a, m);
         }

         //Process data
         error = ccmProcessData(context, block, AES_BLOCK_SIZE, authTag);
      }
      else
      {
         //No additional data
         m = 0;
      }
   }

   //Process the remaining bytes of the associated data
   for(i = m; i < aLen && !error; i += m)
   {
      //Last block?
      if((aLen - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         m = aLen - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, a + i, m);

         //Process data
         error = ccmProcessData(context, block, AES_BLOCK_SIZE, authTag);
      }
      else
      {
         //Process complete blocks only
         m = (aLen - i) - ((aLen - i) % AES_BLOCK_SIZE);

         //Process data
         error = ccmProcessData(context, a + i, m, authTag);
      }
   }

   //Process payload data
   for(i = 0; i < length && !error; i += m)
   {
      //Last block?
      if((length - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         m = length - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, p + i, m);

         //Process data
         error = ccmProcessData(context, block, AES_BLOCK_SIZE, authTag);
      }
      else
      {
         //Process complete blocks only
         m = length - (length % AES_BLOCK_SIZE);

         //Process data
         error = ccmProcessData(context, p, m, authTag);
      }
   }

   //Check status code
   if(!error)
   {
      //Format initial counter value CTR(0)
      ccmFormatCounter0(n, nLen, ctr);

      //Calculate CIPH(CTR0)
      error = aesProcessData(context, NULL, ctr, block, AES_BLOCK_SIZE,
         MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_ENCRYPT);
   }

   //Check status code
   if(!error)
   {
      //Compute MAC
      ccmXorBlock(authTag, authTag, block, tLen);
      //Increment counter block
      ccmIncCounter(ctr, 15 - nLen);
   }

   //Encrypt plaintext
   for(i = 0; i < length && !error; i += m)
   {
      //Last block?
      if((length - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         m = length - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, p + i, m);

         //Process data
         error = aesProcessData(context, ctr, block, block, AES_BLOCK_SIZE,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR, MCUXCLELS_CIPHER_ENCRYPT);

         //Check status code
         if(!error)
         {
            //Copy the partial block
            osMemcpy(c + i, block, m);
         }
      }
      else
      {
         //Process complete blocks only
         m = length - (length % AES_BLOCK_SIZE);

         //Process data
         error = aesProcessData(context, ctr, p + i, c + i, m,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR, MCUXCLELS_CIPHER_ENCRYPT);

         //Increment counter block
         for(j = 0; j < m; j += AES_BLOCK_SIZE)
         {
            ccmIncCounter(ctr, 15 - nLen);
         }
      }
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn547CryptoMutex);

   //Check status code
   if(!error)
   {
      //Copy the resulting authentication tag
      osMemcpy(t, authTag, tLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Authenticated decryption using CCM
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t MAC to be verified
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t ccmDecrypt(const CipherAlgo *cipher, void *context, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p,
   size_t length, const uint8_t *t, size_t tLen)
{
   error_t error;
   size_t i;
   size_t j;
   size_t m;
   uint8_t ctr[AES_BLOCK_SIZE];
   uint8_t block[AES_BLOCK_SIZE];
   uint8_t authTag[AES_BLOCK_SIZE];

   //The ELS module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Make sure the cipher context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format first block B(0)
   error = ccmFormatBlock0(length, n, nLen, aLen, tLen, block);
   //Invalid parameters?
   if(error)
      return error;

   //Format initial counter value CTR(0)
   ccmFormatCounter0(n, nLen, ctr);
   //Increment counter block
   ccmIncCounter(ctr, 15 - nLen);

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn547CryptoMutex);

   //Calculate CIPH(B0)
   error = aesProcessData(context, NULL, block, authTag, AES_BLOCK_SIZE,
      MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_ENCRYPT);

   //Decrypt ciphertext
   for(i = 0; i < length && !error; i += m)
   {
      //Last block?
      if((length - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         m = length - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, c + i, m);

         //Process data
         error = aesProcessData(context, ctr, block, block, AES_BLOCK_SIZE,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR, MCUXCLELS_CIPHER_ENCRYPT);

         //Check status code
         if(!error)
         {
            //Copy the partial block
            osMemcpy(p + i, block, m);
         }
      }
      else
      {
         //Process complete blocks only
         m = length - (length % AES_BLOCK_SIZE);

         //Process data
         error = aesProcessData(context, ctr, c + i, p + i, m,
            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR, MCUXCLELS_CIPHER_ENCRYPT);

         //Increment counter block
         for(j = 0; j < m; j += AES_BLOCK_SIZE)
         {
            ccmIncCounter(ctr, 15 - nLen);
         }
      }
   }

   //Check status code
   if(!error)
   {
      //Any additional data?
      if(aLen > 0)
      {
         //Format the associated data
         osMemset(block, 0, 16);

         //Check the length of the associated data string
         if(aLen < 0xFF00)
         {
            //The length is encoded as 2 octets
            STORE16BE(aLen, block);

            //Number of bytes to copy
            m = MIN(aLen, 16 - 2);
            //Concatenate the associated data A
            osMemcpy(block + 2, a, m);
         }
         else
         {
            //The length is encoded as 6 octets
            block[0] = 0xFF;
            block[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aLen, block + 2);

            //Number of bytes to copy
            m = MIN(aLen, 16 - 6);
            //Concatenate the associated data A
            osMemcpy(block + 6, a, m);
         }

         //Process data
         error = ccmProcessData(context, block, AES_BLOCK_SIZE, authTag);
      }
      else
      {
         //No additional data
         m = 0;
      }
   }

   //Process the remaining bytes of the associated data
   for(i = m; i < aLen && !error; i += m)
   {
      //Last block?
      if((aLen - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         m = aLen - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, a + i, m);

         //Process data
         error = ccmProcessData(context, block, AES_BLOCK_SIZE, authTag);
      }
      else
      {
         //Process complete blocks only
         m = (aLen - i) - ((aLen - i) % AES_BLOCK_SIZE);

         //Process data
         error = ccmProcessData(context, a + i, m, authTag);
      }
   }

   //Process payload data
   for(i = 0; i < length && !error; i += m)
   {
      //Last block?
      if((length - i) < AES_BLOCK_SIZE)
      {
         //Determine the length of the partial block
         m = length - i;

         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, p + i, m);

         //Process data
         error = ccmProcessData(context, block, AES_BLOCK_SIZE, authTag);
      }
      else
      {
         //Process complete blocks only
         m = length - (length % AES_BLOCK_SIZE);

         //Process data
         error = ccmProcessData(context, p, m, authTag);
      }
   }

   //Check status code
   if(!error)
   {
      //Format initial counter value CTR(0)
      ccmFormatCounter0(n, nLen, ctr);

      //Calculate CIPH(CTR0)
      error = aesProcessData(context, NULL, ctr, block, AES_BLOCK_SIZE,
         MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB, MCUXCLELS_CIPHER_ENCRYPT);
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn547CryptoMutex);

   //Check status code
   if(!error)
   {
      uint8_t mask;

      //Compute MAC
      ccmXorBlock(authTag, authTag, block, tLen);

      //The calculated tag is bitwise compared to the received tag
      for(mask = 0, i = 0; i < tLen; i++)
      {
         mask |= authTag[i] ^ t[i];
      }

      //The message is authenticated if and only if the tags match
      error = (mask == 0) ? NO_ERROR : ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
#endif
