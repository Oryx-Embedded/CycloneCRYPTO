/**
 * @file mimxrt1180_crypto_cipher.c
 * @brief i.MX RT1180 cipher hardware accelerator
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
#include "fsl_device_registers.h"
#include "ele_crypto.h"
#include "core/crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1180_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

//ELE input buffer
SDK_ALIGN(static uint8_t eleBufferIn[MIMXRT1180_ELE_BUFFER_SIZE], 16);
//ELE output buffer
SDK_ALIGN(static uint8_t eleBufferOut[MIMXRT1180_ELE_BUFFER_SIZE], 16);
//ELE initialization vector
SDK_ALIGN(static uint8_t eleInitVector[16], 16);

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
   status_t status;
   ele_generic_cipher_t genericCipher;

   //Initialize status code
   status = kStatus_Success;

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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Get the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
         {
            //14 rounds are required for 256-bit key
            keySize = 32;
         }
         else
         {
            //Invalid key length
            status = kStatus_Fail;
         }

         //Check status code
         if(status == kStatus_Success)
         {
            //Acquire exclusive access to the ELE module
            osAcquireMutex(&mimxrt1180CryptoMutex);

            //Perform AES-ECB encryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1180_ELE_BUFFER_SIZE);
               //Copy the plaintext to the buffer
               osMemcpy(eleBufferIn, p + i, n);

               //Set cipher parameters
               genericCipher.data = (uint32_t) eleBufferIn;
               genericCipher.output = (uint32_t) eleBufferOut;
               genericCipher.size = n;
               genericCipher.key = (uint32_t) aesContext->ek;
               genericCipher.key_size = keySize;
               genericCipher.iv = NULL;
               genericCipher.iv_size = 0;
               genericCipher.algo = kAES_ECB;
               genericCipher.mode = kEncrypt;

               //Encrypt data
               status = ELE_GenericCipher(MU_APPS_S3MUA, &genericCipher);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting ciphertext
                  osMemcpy(c + i, eleBufferOut, n);
               }
            }

            //Release exclusive access to the ELE module
            osReleaseMutex(&mimxrt1180CryptoMutex);
         }
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   //Unknown cipher algorithm?
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   ele_generic_cipher_t genericCipher;

   //Initialize status code
   status = kStatus_Success;

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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Get the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
         {
            //14 rounds are required for 256-bit key
            keySize = 32;
         }
         else
         {
            //Invalid key length
            status = kStatus_Fail;
         }

         //Check status code
         if(status == kStatus_Success)
         {
            //Acquire exclusive access to the ELE module
            osAcquireMutex(&mimxrt1180CryptoMutex);

            //Perform AES-ECB decryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1180_ELE_BUFFER_SIZE);
               //Copy the ciphertext to the buffer
               osMemcpy(eleBufferIn, c + i, n);

               //Set cipher parameters
               genericCipher.data = (uint32_t) eleBufferIn;
               genericCipher.output = (uint32_t) eleBufferOut;
               genericCipher.size = n;
               genericCipher.key = (uint32_t) aesContext->ek;
               genericCipher.key_size = keySize;
               genericCipher.iv = NULL;
               genericCipher.iv_size = 0;
               genericCipher.algo = kAES_ECB;
               genericCipher.mode = kDecrypt;

               //Decrypt data
               status = ELE_GenericCipher(MU_APPS_S3MUA, &genericCipher);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting plaintext
                  osMemcpy(p + i, eleBufferOut, n);
               }
            }
         }

         //Release exclusive access to the ELE module
         osReleaseMutex(&mimxrt1180CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   //Unknown cipher algorithm?
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   ele_generic_cipher_t genericCipher;

   //Initialize status code
   status = kStatus_Success;

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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Get the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
         {
            //14 rounds are required for 256-bit key
            keySize = 32;
         }
         else
         {
            //Invalid key length
            status = kStatus_Fail;
         }

         //Check status code
         if(status == kStatus_Success)
         {
            //Acquire exclusive access to the ELE module
            osAcquireMutex(&mimxrt1180CryptoMutex);

            //Perform AES-CBC encryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1180_ELE_BUFFER_SIZE);
               //Copy the plaintext to the buffer
               osMemcpy(eleBufferIn, p + i, n);

               //Set cipher parameters
               genericCipher.data = (uint32_t) eleBufferIn;
               genericCipher.output = (uint32_t) eleBufferOut;
               genericCipher.size = n;
               genericCipher.key = (uint32_t) aesContext->ek;
               genericCipher.key_size = keySize;
               genericCipher.iv = (uint32_t) iv;
               genericCipher.iv_size = AES_BLOCK_SIZE;
               genericCipher.algo = kAES_CBC;
               genericCipher.mode = kEncrypt;

               //Encrypt data
               status = ELE_GenericCipher(MU_APPS_S3MUA, &genericCipher);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting ciphertext
                  osMemcpy(c + i, eleBufferOut, n);
                  //Update the value of the initialization vector
                  osMemcpy(iv, eleBufferOut + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
               }
            }
         }

         //Release exclusive access to the ELE module
         osReleaseMutex(&mimxrt1180CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   //Unknown cipher algorithm?
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   ele_generic_cipher_t genericCipher;

   //Initialize status code
   status = kStatus_Success;

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
         size_t i;
         size_t n;
         size_t keySize;
         AesContext *aesContext;
         uint8_t block[AES_BLOCK_SIZE];

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Get the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
         {
            //14 rounds are required for 256-bit key
            keySize = 32;
         }
         else
         {
            //Invalid key length
            status = kStatus_Fail;
         }

         //Check status code
         if(status == kStatus_Success)
         {
            //Acquire exclusive access to the ELE module
            osAcquireMutex(&mimxrt1180CryptoMutex);

            //Perform AES-CBC decryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               n = MIN(length - i, MIMXRT1180_ELE_BUFFER_SIZE);
               //Copy the ciphertext to the buffer
               osMemcpy(eleBufferIn, c + i, n);
               //Save the last input block
               osMemcpy(block, eleBufferIn + n - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

               //Set cipher parameters
               genericCipher.data = (uint32_t) eleBufferIn;
               genericCipher.output = (uint32_t) eleBufferOut;
               genericCipher.size = n;
               genericCipher.key = (uint32_t) aesContext->ek;
               genericCipher.key_size = keySize;
               genericCipher.iv = (uint32_t) iv;
               genericCipher.iv_size = AES_BLOCK_SIZE;
               genericCipher.algo = kAES_CBC;
               genericCipher.mode = kDecrypt;

               //Decrypt data
               status = ELE_GenericCipher(MU_APPS_S3MUA, &genericCipher);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting plaintext
                  osMemcpy(p + i, eleBufferOut, n);
                  //Update the value of the initialization vector
                  osMemcpy(iv, block, AES_BLOCK_SIZE);
               }
            }
         }

         //Release exclusive access to the ELE module
         osReleaseMutex(&mimxrt1180CryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = kStatus_InvalidArgument;
      }
   }
   //Unknown cipher algorithm?
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
         status = kStatus_InvalidArgument;
      }
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   ele_generic_cipher_t genericCipher;

   //Initialize status code
   status = kStatus_Success;

   //Check the value of the parameter
   if((m % 8) == 0 && m <= (cipher->blockSize * 8))
   {
      //Determine the size, in bytes, of the specific part of the block to be
      //incremented
      m = m / 8;

      //AES cipher algorithm?
      if(cipher == AES_CIPHER_ALGO)
      {
         size_t i;
         size_t k;
         size_t n;
         size_t keySize;
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Get the length of the key
         if(aesContext->nr == 10)
         {
            //10 rounds are required for 128-bit key
            keySize = 16;
         }
         else if(aesContext->nr == 12)
         {
            //12 rounds are required for 192-bit key
            keySize = 24;
         }
         else if(aesContext->nr == 14)
         {
            //14 rounds are required for 256-bit key
            keySize = 32;
         }
         else
         {
            //Invalid key length
            status = kStatus_Fail;
         }

         //Check status code
         if(status == kStatus_Success)
         {
            //Acquire exclusive access to the ELE module
            osAcquireMutex(&mimxrt1180CryptoMutex);

            //Perform AES-CTR encryption
            for(i = 0; i < length && status == kStatus_Success; i += n)
            {
               //Limit the number of data to process at a time
               k = 256 - t[AES_BLOCK_SIZE - 1];
               n = k * AES_BLOCK_SIZE;
               n = MIN(n, length - i);
               n = MIN(n, MIMXRT1180_ELE_BUFFER_SIZE);
               k = (n + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

               //Copy the plaintext to the buffer
               osMemcpy(eleBufferIn, p + i, n);
               //Copy the counter block
               osMemcpy(eleInitVector, t, AES_BLOCK_SIZE);

               //Set cipher parameters
               genericCipher.data = (uint32_t) eleBufferIn;
               genericCipher.output = (uint32_t) eleBufferOut;
               genericCipher.size = k * AES_BLOCK_SIZE;
               genericCipher.key = (uint32_t) aesContext->ek;
               genericCipher.key_size = keySize;
               genericCipher.iv = (uint32_t) eleInitVector;
               genericCipher.iv_size = AES_BLOCK_SIZE;
               genericCipher.algo = kAES_CTR;
               genericCipher.mode = kEncrypt;

               //Encrypt data
               status = ELE_GenericCipher(MU_APPS_S3MUA, &genericCipher);

               //Check status code
               if(status == kStatus_Success)
               {
                  //Copy the resulting ciphertext
                  osMemcpy(c + i, eleBufferOut, n);
                  //Update the value of the counter block
                  ctrIncBlock(t, k, AES_BLOCK_SIZE, m);
               }
            }
         }

         //Release exclusive access to the ELE module
         osReleaseMutex(&mimxrt1180CryptoMutex);
      }
      //Unknown cipher algorithm?
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
      status = kStatus_InvalidArgument;
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (GCM_SUPPORT == ENABLED)

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
   status_t status;
   size_t keySize;
   AesContext *aesContext;
   ele_generic_aead_t genericAead;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   status = kStatus_Success;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Get the length of the key
   if(aesContext->nr == 10)
   {
      //10 rounds are required for 128-bit key
      keySize = 16;
   }
   else if(aesContext->nr == 12)
   {
      //12 rounds are required for 192-bit key
      keySize = 24;
   }
   else if(aesContext->nr == 14)
   {
      //14 rounds are required for 256-bit key
      keySize = 32;
   }
   else
   {
      //Invalid key length
      status = kStatus_Fail;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Acquire exclusive access to the ELE module
      osAcquireMutex(&mimxrt1180CryptoMutex);

      //Set cipher parameters
      genericAead.data = (uint32_t) p;
      genericAead.output = (uint32_t) c;
      genericAead.size = length;
      genericAead.key = (uint32_t) aesContext->ek;
      genericAead.key_size = keySize;
      genericAead.iv = (uint32_t) iv;
      genericAead.iv_size = ivLen;
      genericAead.aad = (uint32_t) a;
      genericAead.aad_size = aLen;
      genericAead.tag = (uint32_t) t;
      genericAead.tag_size = tLen;
      genericAead.algo = kAES_GCM;
      genericAead.mode = kEncrypt;

      //Perform AES-GCM encryption
      status = ELE_GenericAead(MU_APPS_S3MUA, &genericAead);

      //Release exclusive access to the ELE module
      osReleaseMutex(&mimxrt1180CryptoMutex);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   size_t keySize;
   AesContext *aesContext;
   ele_generic_aead_t genericAead;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   status = kStatus_Success;

   //Point to the AES context
   aesContext = (AesContext *) context->cipherContext;

   //Get the length of the key
   if(aesContext->nr == 10)
   {
      //10 rounds are required for 128-bit key
      keySize = 16;
   }
   else if(aesContext->nr == 12)
   {
      //12 rounds are required for 192-bit key
      keySize = 24;
   }
   else if(aesContext->nr == 14)
   {
      //14 rounds are required for 256-bit key
      keySize = 32;
   }
   else
   {
      //Invalid key length
      status = kStatus_Fail;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Acquire exclusive access to the ELE module
      osAcquireMutex(&mimxrt1180CryptoMutex);

      //Set cipher parameters
      genericAead.data = (uint32_t) c;
      genericAead.output = (uint32_t) p;
      genericAead.size = length;
      genericAead.key = (uint32_t) aesContext->ek;
      genericAead.key_size = keySize;
      genericAead.iv = (uint32_t) iv;
      genericAead.iv_size = ivLen;
      genericAead.aad = (uint32_t) a;
      genericAead.aad_size = aLen;
      genericAead.tag = (uint32_t) t;
      genericAead.tag_size = tLen;
      genericAead.algo = kAES_GCM;
      genericAead.mode = kDecrypt;

      //Perform AES-GCM decryption
      status = ELE_GenericAead(MU_APPS_S3MUA, &genericAead);

      //Release exclusive access to the ELE module
      osReleaseMutex(&mimxrt1180CryptoMutex);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   size_t keySize;
   AesContext *aesContext;
   ele_generic_aead_t genericAead;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   status = kStatus_Success;

   //Point to the AES context
   aesContext = (AesContext *) context;

   //Get the length of the key
   if(aesContext->nr == 10)
   {
      //10 rounds are required for 128-bit key
      keySize = 16;
   }
   else if(aesContext->nr == 12)
   {
      //12 rounds are required for 192-bit key
      keySize = 24;
   }
   else if(aesContext->nr == 14)
   {
      //14 rounds are required for 256-bit key
      keySize = 32;
   }
   else
   {
      //Invalid key length
      status = kStatus_Fail;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Acquire exclusive access to the ELE module
      osAcquireMutex(&mimxrt1180CryptoMutex);

      //Set cipher parameters
      genericAead.data = (uint32_t) p;
      genericAead.output = (uint32_t) c;
      genericAead.size = length;
      genericAead.key = (uint32_t) aesContext->ek;
      genericAead.key_size = keySize;
      genericAead.iv = (uint32_t) n;
      genericAead.iv_size = nLen;
      genericAead.aad = (uint32_t) a;
      genericAead.aad_size = aLen;
      genericAead.tag = (uint32_t) t;
      genericAead.tag_size = tLen;
      genericAead.algo = kAES_CCM;
      genericAead.mode = kEncrypt;

      //Perform AES-CCM encryption
      status = ELE_GenericAead(MU_APPS_S3MUA, &genericAead);

      //Release exclusive access to the ELE module
      osReleaseMutex(&mimxrt1180CryptoMutex);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
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
   status_t status;
   size_t keySize;
   AesContext *aesContext;
   ele_generic_aead_t genericAead;

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   status = kStatus_Success;

   //Point to the AES context
   aesContext = (AesContext *) context;

   //Get the length of the key
   if(aesContext->nr == 10)
   {
      //10 rounds are required for 128-bit key
      keySize = 16;
   }
   else if(aesContext->nr == 12)
   {
      //12 rounds are required for 192-bit key
      keySize = 24;
   }
   else if(aesContext->nr == 14)
   {
      //14 rounds are required for 256-bit key
      keySize = 32;
   }
   else
   {
      //Invalid key length
      status = kStatus_Fail;
   }

   //Check status code
   if(status == kStatus_Success)
   {
      //Acquire exclusive access to the ELE module
      osAcquireMutex(&mimxrt1180CryptoMutex);

      //Set cipher parameters
      genericAead.data = (uint32_t) c;
      genericAead.output = (uint32_t) p;
      genericAead.size = length;
      genericAead.key = (uint32_t) aesContext->ek;
      genericAead.key_size = keySize;
      genericAead.iv = (uint32_t) n;
      genericAead.iv_size = nLen;
      genericAead.aad = (uint32_t) a;
      genericAead.aad_size = aLen;
      genericAead.tag = (uint32_t) t;
      genericAead.tag_size = tLen;
      genericAead.algo = kAES_CCM;
      genericAead.mode = kDecrypt;

      //Perform AES-CCM decryption
      status = ELE_GenericAead(MU_APPS_S3MUA, &genericAead);

      //Release exclusive access to the ELE module
      osReleaseMutex(&mimxrt1180CryptoMutex);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif
