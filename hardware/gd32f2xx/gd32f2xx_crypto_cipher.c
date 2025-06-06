/**
 * @file gd32f2xx_crypto_cipher.c
 * @brief GD32F2 cipher hardware accelerator
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
#include "gd32f20x.h"
#include "gd32f20x_cau.h"
#include "core/crypto.h"
#include "hardware/gd32f2xx/gd32f2xx_crypto.h"
#include "hardware/gd32f2xx/gd32f2xx_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "debug.h"

//Check crypto library configuration
#if (GD32F2XX_CRYPTO_CIPHER_SUPPORT == ENABLED)


/**
 * @brief CAU module initialization
 * @return Error code
 **/

error_t cauInit(void)
{
   //Enable CAU peripheral clock
   rcu_periph_clock_enable(RCU_CAU);

   //Successful processing
   return NO_ERROR;
}


#if (DES_SUPPORT == ENABLED)

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

   //Copy the key
   osMemcpy(context->ks, key, keyLen);

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
   cau_text_struct text;

   //Specify input and output data
   text.input = (uint8_t *) input;
   text.output = output;
   text.in_length = DES_BLOCK_SIZE;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Perform DES encryption
   cau_des_ecb(CAU_ENCRYPT, (uint8_t *) context->ks, &text);
   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);
}


/**
 * @brief Decrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void desDecryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   cau_text_struct text;

   //Specify input and output data
   text.input = (uint8_t *) input;
   text.output = output;
   text.in_length = DES_BLOCK_SIZE;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Perform DES decryption
   cau_des_ecb(CAU_DECRYPT, (uint8_t *) context->ks, &text);
   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);
}

#endif
#if (DES3_SUPPORT == ENABLED)

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

   //Invalid key length?
   if(keyLen != 8 && keyLen != 16 && keyLen != 24)
      return ERROR_INVALID_KEY_LENGTH;

   //Copy the key
   osMemcpy(context->k1.ks, key, keyLen);

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
   cau_text_struct text;

   //Specify input and output data
   text.input = (uint8_t *) input;
   text.output = output;
   text.in_length = DES3_BLOCK_SIZE;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Perform 3DES encryption
   cau_tdes_ecb(CAU_ENCRYPT, (uint8_t *) context->k1.ks, &text);
   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void des3DecryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   cau_text_struct text;

   //Specify input and output data
   text.input = (uint8_t *) input;
   text.output = output;
   text.in_length = DES3_BLOCK_SIZE;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Perform 3DES decryption
   cau_tdes_ecb(CAU_DECRYPT, (uint8_t *) context->k1.ks, &text);
   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);
}

#endif
#if (AES_SUPPORT == ENABLED)

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

   //Invalid key length?
   if(keyLen != 16 && keyLen != 24 && keyLen != 32)
      return ERROR_INVALID_KEY_LENGTH;

   //Copy the key
   osMemcpy(context->ek, key, keyLen);

   //Save the length of the key in bits
   context->nr = keyLen * 8;

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
   cau_text_struct text;

   //Specify input and output data
   text.input = (uint8_t *) input;
   text.output = output;
   text.in_length = AES_BLOCK_SIZE;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Perform AES encryption
   cau_aes_ecb(CAU_ENCRYPT, (uint8_t *) context->ek, context->nr, &text);
   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);
}


/**
 * @brief Decrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void aesDecryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
   cau_text_struct text;

   //Specify input and output data
   text.input = (uint8_t *) input;
   text.output = output;
   text.in_length = AES_BLOCK_SIZE;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Perform AES decryption
   cau_aes_ecb(CAU_DECRYPT, (uint8_t *) context->ek, context->nr, &text);
   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);
}

#endif
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
   ErrStatus status;
   cau_text_struct text;

   //Initialize status code
   status = SUCCESS;

   //Specify input and output data
   text.input = (uint8_t *) p;
   text.output = c;
   text.in_length = length;

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
         DesContext *desContext;

         //Point to the DES context
         desContext = (DesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform DES-ECB encryption
         status = cau_des_ecb(CAU_ENCRYPT, (uint8_t *) desContext->ks, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform 3DES-ECB encryption
         status = cau_tdes_ecb(CAU_ENCRYPT, (uint8_t *) des3Context->k1.ks, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform AES-ECB encryption
         status = cau_aes_ecb(CAU_ENCRYPT, (uint8_t *) aesContext->ek,
            aesContext->nr, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         status = ERROR;
      }
   }

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   ErrStatus status;
   cau_text_struct text;

   //Initialize status code
   status = SUCCESS;

   //Specify input and output data
   text.input = (uint8_t *) c;
   text.output = p;
   text.in_length = length;

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
         DesContext *desContext;

         //Point to the DES context
         desContext = (DesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform DES-ECB decryption
         status = cau_des_ecb(CAU_DECRYPT, (uint8_t *) desContext->ks, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform 3DES-ECB decryption
         status = cau_tdes_ecb(CAU_DECRYPT, (uint8_t *) des3Context->k1.ks, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform AES-ECB decryption
         status = cau_aes_ecb(CAU_DECRYPT, (uint8_t *) aesContext->ek,
            aesContext->nr, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         status = ERROR;
      }
   }

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   ErrStatus status;
   cau_text_struct text;

   //Initialize status code
   status = SUCCESS;

   //Specify input and output data
   text.input = (uint8_t *) p;
   text.output = c;
   text.in_length = length;

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
         DesContext *desContext;

         //Point to the DES context
         desContext = (DesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform DES-CBC encryption
         status = cau_des_cbc(CAU_ENCRYPT, (uint8_t *) desContext->ks, iv, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform 3DES-ECB encryption
         status = cau_tdes_cbc(CAU_ENCRYPT, (uint8_t *) des3Context->k1.ks, iv, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform AES-CBC encryption
         status = cau_aes_cbc(CAU_ENCRYPT, (uint8_t *) aesContext->ek,
            aesContext->nr, iv, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         status = ERROR;
      }
   }

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   ErrStatus status;
   cau_text_struct text;

   //Initialize status code
   status = SUCCESS;

   //Specify input and output data
   text.input = (uint8_t *) c;
   text.output = p;
   text.in_length = length;

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
         DesContext *desContext;

         //Point to the DES context
         desContext = (DesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform DES-CBC decryption
         status = cau_des_cbc(CAU_DECRYPT, (uint8_t *) desContext->ks, iv, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         Des3Context *des3Context;

         //Point to the Triple DES context
         des3Context = (Des3Context *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform 3DES-ECB decryption
         status = cau_tdes_cbc(CAU_DECRYPT, (uint8_t *) des3Context->k1.ks, iv, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);
         //Perform AES-CBC decryption
         status = cau_aes_cbc(CAU_DECRYPT, (uint8_t *) aesContext->ek,
            aesContext->nr, iv, &text);
         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
      }
      else
      {
         //The length of the payload must be a multiple of the block size
         status = ERROR;
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
         status = ERROR;
      }
   }

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   ErrStatus status;
   cau_text_struct text;

   //Initialize status code
   status = SUCCESS;

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
         AesContext *aesContext;

         //Point to the AES context
         aesContext = (AesContext *) context;

         //Acquire exclusive access to the CAU module
         osAcquireMutex(&gd32f2xxCryptoMutex);

         //Process plaintext
         while(length > 0 && status == SUCCESS)
         {
            //Limit the number of blocks to process at a time
            k = 256 - t[AES_BLOCK_SIZE - 1];
            n = MIN(length, k * AES_BLOCK_SIZE);
            k = (n + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

            //Specify input and output data
            text.input = (uint8_t *) p;
            text.output = c;
            text.in_length = n;

            //Perform AES-CTR encryption
            status = cau_aes_ctr(CAU_ENCRYPT, (uint8_t *) aesContext->ek,
               aesContext->nr, t, &text);

            //Standard incrementing function
            ctrIncBlock(t, k, AES_BLOCK_SIZE, m);

            //Next block
            p += n;
            c += n;
            length -= n;
         }

         //Release exclusive access to the CAU module
         osReleaseMutex(&gd32f2xxCryptoMutex);
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
      status = ERROR;
   }

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif
