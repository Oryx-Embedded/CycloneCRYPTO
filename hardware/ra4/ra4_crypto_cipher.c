/**
 * @file ra4_crypto_cipher.c
 * @brief RA4 cipher hardware accelerator
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
#include "hw_sce_private.h"
#include "hw_sce_ra_private.h"
#include "hw_sce_aes_private.h"
#include "core/crypto.h"
#include "hardware/ra4/ra4_crypto.h"
#include "hardware/ra4/ra4_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (RA4_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Perform AES encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] command Operation mode
 * @return Status code
 **/

error_t aesProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t command)
{
   fsp_err_t status;
   size_t n;
   uint32_t keyType;
   uint32_t block[AES_BLOCK_SIZE / 4];

   //Set key type
   keyType = 0;
   //Set operation mode
   command = htobe32(command);

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra4CryptoMutex);

   //Initialize encryption or decryption operation
   if(context->nr == 10)
   {
      status = HW_SCE_Aes128EncryptDecryptInitSub(&keyType, &command,
         context->ek, (const uint32_t *) iv);
   }
   else if(context->nr == 12)
   {
      status = HW_SCE_Aes192EncryptDecryptInitSub(&command,
         context->ek, (const uint32_t *) iv);
   }
   else if(context->nr == 14)
   {
      status = HW_SCE_Aes256EncryptDecryptInitSub(&keyType, &command,
         context->ek, (const uint32_t *) iv);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Get the number of bytes in the last block
      n = length % AES_BLOCK_SIZE;

      //Process complete blocks only
      if(context->nr == 10)
      {
         HW_SCE_Aes128EncryptDecryptUpdateSub((const uint32_t *) input,
            (uint32_t *) output, (length - n) / 4);
      }
      else if(context->nr == 12)
      {
         HW_SCE_Aes192EncryptDecryptUpdateSub((const uint32_t *) input,
            (uint32_t *) output, (length - n) / 4);
      }
      else
      {
         HW_SCE_Aes256EncryptDecryptUpdateSub((const uint32_t *) input,
            (uint32_t *) output, (length - n) / 4);
      }

      //The final block requires special processing
      if(n > 0)
      {
         //Copy the input data
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, input + length - n, n);

         //Process the final block
         if(context->nr == 10)
         {
            HW_SCE_Aes128EncryptDecryptUpdateSub(block, block,
               AES_BLOCK_SIZE / 4);
         }
         else if(context->nr == 12)
         {
            HW_SCE_Aes192EncryptDecryptUpdateSub(block, block,
               AES_BLOCK_SIZE / 4);
         }
         else
         {
            HW_SCE_Aes256EncryptDecryptUpdateSub(block, block,
               AES_BLOCK_SIZE / 4);
         }

         //Copy the resulting ciphertext
         osMemcpy(output + length - n, block, n);
      }
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Finalize encryption or decryption operation
      if(context->nr == 10)
      {
         status = HW_SCE_Aes128EncryptDecryptFinalSub();
      }
      else if(context->nr == 12)
      {
         status = HW_SCE_Aes192EncryptDecryptFinalSub();
      }
      else if(context->nr == 14)
      {
         status = HW_SCE_Aes256EncryptDecryptFinalSub();
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Check status code
   if(status != FSP_SUCCESS)
   {
      osMemset(output, 0, length);
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra4CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   fsp_err_t status;

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra4CryptoMutex);

   //Check the length of the key
   if(keyLen == 16)
   {
      //10 rounds are required for 128-bit key
      context->nr = 10;

      //Install the plaintext key and get the wrapped key
      status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
         SCE_OEM_CMD_AES128, NULL, NULL, key, context->ek);
   }
   else if(keyLen == 24)
   {
      //12 rounds are required for 192-bit key
      context->nr = 12;

      //Install the plaintext key and get the wrapped key
      status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
         SCE_OEM_CMD_AES192, NULL, NULL, key, context->ek);
   }
   else if(keyLen == 32)
   {
      //14 rounds are required for 256-bit key
      context->nr = 14;

      //Install the plaintext key and get the wrapped key
      status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
         SCE_OEM_CMD_AES256, NULL, NULL, key, context->ek);
   }
   else
   {
      //Invalid key length
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra4CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
      SCE_AES_IN_DATA_CMD_ECB_ENCRYPTION);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform AES decryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE,
      SCE_AES_IN_DATA_CMD_ECB_DECRYPTION);
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
            SCE_AES_IN_DATA_CMD_ECB_ENCRYPTION);
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
            SCE_AES_IN_DATA_CMD_ECB_DECRYPTION);
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
            SCE_AES_IN_DATA_CMD_CBC_ENCRYPTION);

         //Check status code
         if(!error)
         {
            //Update the value of the initialization vector
            osMemcpy(iv, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
         }
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
         uint8_t block[AES_BLOCK_SIZE];

         //Save the last input block
         osMemcpy(block, c + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

         //Decrypt payload data
         error = aesProcessData(context, iv, c, p, length,
            SCE_AES_IN_DATA_CMD_CBC_DECRYPTION);

         //Check status code
         if(!error)
         {
            //Update the value of the initialization vector
            osMemcpy(iv, block, AES_BLOCK_SIZE);
         }
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
#if (CTR_SUPPORT == ENABLED)

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
      //Determine the size, in bytes, of the specific part of the block to be
      //incremented
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
               SCE_AES_IN_DATA_CMD_CTR_ENCRYPTION_DECRYPTION);

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
#if (GCM_SUPPORT == ENABLED && BSP_FEATURE_RSIP_SCE9_SUPPORTED != 0)

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

   //The SCE module only supports AES cipher algorithm
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
   fsp_err_t status;
   size_t i;
   size_t n;
   uint64_t m;
   uint32_t keyType;
   uint32_t temp[4];
   uint32_t block[4];
   uint32_t authTag[4];
   AesContext *aesContext;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Set key type
   keyType = 0;

   //When the length of the IV is 96 bits, the padding string is appended to
   //the IV to form the pre-counter block
   temp[0] = LOAD32LE(iv);
   temp[1] = LOAD32LE(iv + 4);
   temp[2] = LOAD32LE(iv + 8);
   temp[3] = BETOH32(1);

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra4CryptoMutex);

   //Initialize GCM encryption
   if(aesContext->nr == 10)
   {
      status = HW_SCE_Aes128GcmEncryptInitSub(&keyType, aesContext->ek, temp);
   }
   else if(aesContext->nr == 12)
   {
      status = HW_SCE_Aes192GcmEncryptInitSub(aesContext->ek, temp);
   }
   else if(aesContext->nr == 14)
   {
      status = HW_SCE_Aes256GcmEncryptInitSub(&keyType, aesContext->ek, temp);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Point to the beginning of the additional authenticated data
      i = 0;

      //Process additional authenticated data
      if(aLen >= AES_BLOCK_SIZE)
      {
         //Process complete blocks only
         n = aLen - (aLen % AES_BLOCK_SIZE);

         //Write complete blocks
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128GcmEncryptUpdateAADSub((uint32_t *) a, n / 4);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192GcmEncryptUpdateAADSub((uint32_t *) a, n / 4);
         }
         else
         {
            HW_SCE_Aes256GcmEncryptUpdateAADSub((uint32_t *) a, n / 4);
         }

         //Advance data pointer
         i += n;
      }

      //Process final block of additional authenticated data
      if(i < aLen)
      {
         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, a + i, aLen - i);

         //Write block
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128GcmEncryptUpdateAADSub(block, 1);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192GcmEncryptUpdateAADSub(block, 1);
         }
         else
         {
            HW_SCE_Aes256GcmEncryptUpdateAADSub(block, 1);
         }
      }

      //Transition to from AAD phase to data phase
      if(aesContext->nr == 10)
      {
         HW_SCE_Aes128GcmEncryptUpdateTransitionSub();
      }
      else if(aesContext->nr == 12)
      {
         HW_SCE_Aes192GcmEncryptUpdateTransitionSub();
      }
      else
      {
         HW_SCE_Aes256GcmEncryptUpdateTransitionSub();
      }

      //Point to the beginning of the payload data
      i = 0;

      //Process payload data
      if(length >= AES_BLOCK_SIZE)
      {
         //Process complete blocks only
         n = length - (length % AES_BLOCK_SIZE);

         //Encrypt complete blocks
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128GcmEncryptUpdateSub((uint32_t *) p, (uint32_t *) c,
               n / 4);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192GcmEncryptUpdateSub((uint32_t *) p, (uint32_t *) c,
               n / 4);
         }
         else
         {
            HW_SCE_Aes256GcmEncryptUpdateSub((uint32_t *) p, (uint32_t *) c,
               n / 4);
         }

         //Advance data pointer
         i += n;
      }

      //Process final block of payload data
      if(i < length)
      {
         //Copy the partial input block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, p + i, length - i);
      }

      //64-bit representation of the length of the payload data
      m = length * 8;
      temp[0] = htobe32(m >> 32);
      temp[1] = htobe32(m);

      //64-bit representation of the length of the additional data
      m = aLen * 8;
      temp[2] = htobe32(m >> 32);
      temp[3] = htobe32(m);

      //Generate authentication tag
      if(aesContext->nr == 10)
      {
         status = HW_SCE_Aes128GcmEncryptFinalSub(block, temp, temp + 2,
            block, authTag);
      }
      else if(aesContext->nr == 12)
      {
         status = HW_SCE_Aes192GcmEncryptFinalSub(block, temp, temp + 2,
            block, authTag);
      }
      else if(aesContext->nr == 14)
      {
         status = HW_SCE_Aes256GcmEncryptFinalSub(block, temp, temp + 2,
            block, authTag);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the partial output block
      osMemcpy(c + i, block, length - i);
      //Copy the resulting authentication tag
      osMemcpy(t, authTag, tLen);
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra4CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   fsp_err_t status;
   size_t i;
   size_t n;
   uint64_t m;
   uint32_t keyType;
   uint32_t temp[5];
   uint32_t block[4];
   uint32_t authTag[4];
   AesContext *aesContext;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen != 12)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Set key type
   keyType = 0;

   //When the length of the IV is 96 bits, the padding string is appended to
   //the IV to form the pre-counter block
   temp[0] = LOAD32LE(iv);
   temp[1] = LOAD32LE(iv + 4);
   temp[2] = LOAD32LE(iv + 8);
   temp[3] = BETOH32(1);

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra4CryptoMutex);

   //Initialize GCM decryption
   if(aesContext->nr == 10)
   {
      status = HW_SCE_Aes128GcmDecryptInitSub(&keyType, aesContext->ek, temp);
   }
   else if(aesContext->nr == 12)
   {
      status = HW_SCE_Aes192GcmDecryptInitSub(aesContext->ek, temp);
   }
   else if(aesContext->nr == 14)
   {
      status = HW_SCE_Aes256GcmDecryptInitSub(&keyType, aesContext->ek, temp);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Point to the beginning of the additional authenticated data
      i = 0;

      //Process additional authenticated data
      if(aLen >= AES_BLOCK_SIZE)
      {
         //Process complete blocks only
         n = aLen - (aLen % AES_BLOCK_SIZE);

         //Write complete blocks
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128GcmDecryptUpdateAADSub((uint32_t *) a, n / 4);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192GcmDecryptUpdateAADSub((uint32_t *) a, n / 4);
         }
         else
         {
            HW_SCE_Aes256GcmDecryptUpdateAADSub((uint32_t *) a, n / 4);
         }

         //Advance data pointer
         i += n;
      }

      //Process final block of additional authenticated data
      if(i < aLen)
      {
         //Copy the partial block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, a + i, aLen - i);

         //Write block
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128GcmDecryptUpdateAADSub(block, 1);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192GcmDecryptUpdateAADSub(block, 1);
         }
         else
         {
            HW_SCE_Aes256GcmDecryptUpdateAADSub(block, 1);
         }
      }

      //Transition to from AAD phase to data phase
      if(aesContext->nr == 10)
      {
         HW_SCE_Aes128GcmDecryptUpdateTransitionSub();
      }
      else if(aesContext->nr == 12)
      {
         HW_SCE_Aes192GcmDecryptUpdateTransitionSub();
      }
      else
      {
         HW_SCE_Aes256GcmDecryptUpdateTransitionSub();
      }

      //Point to the beginning of the payload data
      i = 0;

      //Process payload data
      if(length >= AES_BLOCK_SIZE)
      {
         //Process complete blocks only
         n = length - (length % AES_BLOCK_SIZE);

         //Decrypt complete blocks
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128GcmDecryptUpdateSub((uint32_t *) c, (uint32_t *) p,
               n / 4);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192GcmDecryptUpdateSub((uint32_t *) c, (uint32_t *) p,
               n / 4);
         }
         else
         {
            HW_SCE_Aes256GcmDecryptUpdateSub((uint32_t *) c, (uint32_t *) p,
               n / 4);
         }

         //Advance data pointer
         i += n;
      }

      //Process final block of payload data
      if(i < length)
      {
         //Copy the partial input block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, c + i, length - i);
      }

      //64-bit representation of the length of the payload data
      m = length * 8;
      temp[0] = htobe32(m >> 32);
      temp[1] = htobe32(m);

      //64-bit representation of the length of the additional data
      m = aLen * 8;
      temp[2] = htobe32(m >> 32);
      temp[3] = htobe32(m);

      //32-bit representation of the length of the authentication tag
      temp[4] = htobe32(tLen);

      //Pad the authentication tag
      osMemset(authTag, 0, sizeof(authTag));
      osMemcpy(authTag, t, tLen);

      //Verify authentication tag
      if(aesContext->nr == 10)
      {
         status = HW_SCE_Aes128GcmDecryptFinalSub(block, temp, temp + 2,
            authTag, temp + 4, block);
      }
      else if(aesContext->nr == 12)
      {
         status = HW_SCE_Aes192GcmDecryptFinalSub(block, temp, temp + 2,
            authTag, temp + 4, block);
      }
      else if(aesContext->nr == 14)
      {
         status = HW_SCE_Aes256GcmDecryptFinalSub(block, temp, temp + 2,
            authTag, temp + 4, block);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the partial output block
      osMemcpy(p + i, block, length - i);
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra4CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (CCM_SUPPORT == ENABLED)

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
   fsp_err_t status;
   size_t m;
   uint32_t keyType;
   uint32_t dataType;
   uint32_t command;
   uint32_t textLen;
   uint32_t headerLen;
   uint32_t seqNum;
   uint32_t block[4];
   uint32_t authTag[4];
   uint8_t header[64];
   AesContext *aesContext;

   //The SCE module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Make sure the cipher context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the additional data
   if(aLen > (sizeof(header) - 18))
      return ERROR_INVALID_LENGTH;

   //Point to the AES context
   aesContext = (AesContext *) context;

   //Initialize parameters
   keyType = 0;
   dataType = 0;
   command = 0;
   textLen = htobe32(length);
   seqNum = 0;

   //Clear header
   osMemset(header, 0, sizeof(header));

   //Format first block B(0)
   error = ccmFormatBlock0(length, n, nLen, aLen, tLen, header);
   //Invalid parameters?
   if(error)
      return error;

   //Size of the first block (B0)
   headerLen = AES_BLOCK_SIZE;

   //Any additional data?
   if(aLen > 0)
   {
      //The length is encoded as 2 octets
      STORE16BE(aLen, header + headerLen);
      //Concatenate the associated data A
      osMemcpy(header + headerLen + 2, a, aLen);
      //Adjust the size of the header
      headerLen += 2 + aLen;
   }

   //Format initial counter value CTR(0)
   ccmFormatCounter0(n, nLen, (uint8_t *) block);

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra4CryptoMutex);

   //Initialize CCM encryption
   if(aesContext->nr == 10)
   {
      status = HW_SCE_Aes128CcmEncryptInitSubGeneral(&keyType, &dataType,
         &command, &textLen, aesContext->ek, block, (uint32_t *) header,
         &seqNum, (headerLen + 3) / 4);
   }
   else if(aesContext->nr == 12)
   {
      status = HW_SCE_Aes192CcmEncryptInitSubGeneral(&keyType, &dataType,
         &command, &textLen, aesContext->ek, block, (uint32_t *) header,
         &seqNum, (headerLen + 3) / 4);
   }
   else if(aesContext->nr == 14)
   {
      status = HW_SCE_Aes256CcmEncryptInitSubGeneral(&keyType, &dataType,
         &command, &textLen, aesContext->ek, block, (uint32_t *) header,
         &seqNum, (headerLen + 3) / 4);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Process payload data
      if(length >= AES_BLOCK_SIZE)
      {
         //Process complete blocks only
         m = length - (length % AES_BLOCK_SIZE);

         //Encrypt complete blocks
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128CcmEncryptUpdateSub((uint32_t *) p, (uint32_t *) c,
               m / 4);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192CcmEncryptUpdateSub((uint32_t *) p, (uint32_t *) c,
               m / 4);
         }
         else
         {
            HW_SCE_Aes256CcmEncryptUpdateSub((uint32_t *) p, (uint32_t *) c,
               m / 4);
         }

         //Advance data pointer
         length -= m;
         p += m;
         c += m;
      }

      //Process final block of payload data
      if(length > 0)
      {
         //Copy the partial input block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, p, length);
      }

      //Generate authentication tag
      if(aesContext->nr == 10)
      {
         status = HW_SCE_Aes128CcmEncryptFinalSubGeneral(block, &textLen,
            block, authTag);
      }
      else if(aesContext->nr == 12)
      {
         status = HW_SCE_Aes192CcmEncryptFinalSub(block, &textLen, block,
            authTag);
      }
      else if(aesContext->nr == 14)
      {
         status = HW_SCE_Aes256CcmEncryptFinalSub(block, &textLen, block,
            authTag);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the partial output block
      osMemcpy(c, block, length);
      //Copy the resulting authentication tag
      osMemcpy(t, authTag, tLen);
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra4CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   fsp_err_t status;
   size_t m;
   uint32_t keyType;
   uint32_t dataType;
   uint32_t command;
   uint32_t textLen;
   uint32_t authTagLen;
   uint32_t headerLen;
   uint32_t seqNum;
   uint32_t block[4];
   uint32_t authTag[4];
   uint8_t header[64];
   AesContext *aesContext;

   //The SCE module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Make sure the cipher context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the additional data
   if(aLen > (sizeof(header) - 18))
      return ERROR_INVALID_LENGTH;

   //Point to the AES context
   aesContext = (AesContext *) context;

   //Initialize parameters
   keyType = 0;
   dataType = 0;
   command = 0;
   textLen = htobe32(length);
   authTagLen = htobe32(tLen);
   seqNum = 0;

   //Clear header
   osMemset(header, 0, sizeof(header));

   //Format first block B(0)
   error = ccmFormatBlock0(length, n, nLen, aLen, tLen, header);
   //Invalid parameters?
   if(error)
      return error;

   //Size of the first block (B0)
   headerLen = AES_BLOCK_SIZE;

   //Any additional data?
   if(aLen > 0)
   {
      //The length is encoded as 2 octets
      STORE16BE(aLen, header + headerLen);
      //Concatenate the associated data A
      osMemcpy(header + headerLen + 2, a, aLen);
      //Adjust the size of the header
      headerLen += 2 + aLen;
   }

   //Format initial counter value CTR(0)
   ccmFormatCounter0(n, nLen, (uint8_t *) block);

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra4CryptoMutex);

   //Initialize CCM decryption
   if(aesContext->nr == 10)
   {
      status = HW_SCE_Aes128CcmDecryptInitSubGeneral(&keyType, &dataType,
         &command, &textLen, &authTagLen, aesContext->ek, block,
         (uint32_t *) header, &seqNum, (headerLen + 3) / 4);
   }
   else if(aesContext->nr == 12)
   {
      status = HW_SCE_Aes192CcmDecryptInitSubGeneral(&keyType, &dataType,
         &command, &textLen, &authTagLen, aesContext->ek, block,
         (uint32_t *) header, &seqNum, (headerLen + 3) / 4);
   }
   else if(aesContext->nr == 14)
   {
      status = HW_SCE_Aes256CcmDecryptInitSubGeneral(&keyType, &dataType,
         &command, &textLen, &authTagLen, aesContext->ek, block,
         (uint32_t *) header, &seqNum, (headerLen + 3) / 4);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Process payload data
      if(length >= AES_BLOCK_SIZE)
      {
         //Process complete blocks only
         m = length - (length % AES_BLOCK_SIZE);

         //Decrypt complete blocks
         if(aesContext->nr == 10)
         {
            HW_SCE_Aes128CcmDecryptUpdateSub((uint32_t *) c, (uint32_t *) p,
               m / 4);
         }
         else if(aesContext->nr == 12)
         {
            HW_SCE_Aes192CcmDecryptUpdateSub((uint32_t *) c, (uint32_t *) p,
               m / 4);
         }
         else
         {
            HW_SCE_Aes256CcmDecryptUpdateSub((uint32_t *) c, (uint32_t *) p,
               m / 4);
         }

         //Advance data pointer
         length -= m;
         c += m;
         p += m;
      }

      //Process final block of payload data
      if(length > 0)
      {
         //Copy the partial input block
         osMemset(block, 0, AES_BLOCK_SIZE);
         osMemcpy(block, c, length);
      }

      //Pad the authentication tag
      osMemset(authTag, 0, sizeof(authTag));
      osMemcpy(authTag, t, tLen);

      //Verify authentication tag
      if(aesContext->nr == 10)
      {
         status = HW_SCE_Aes128CcmDecryptFinalSubGeneral(block, &textLen,
            authTag, &authTagLen, block);
      }
      else if(aesContext->nr == 12)
      {
         status = HW_SCE_Aes192CcmDecryptFinalSub(block, &textLen,
            authTag, &authTagLen, block);
      }
      else if(aesContext->nr == 14)
      {
         status = HW_SCE_Aes256CcmDecryptFinalSub(block, &textLen,
            authTag, &authTagLen, block);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the partial output block
      osMemcpy(p, block, length);
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra4CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif
