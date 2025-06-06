/**
 * @file gd32h7xx_crypto_cipher.c
 * @brief GD32H7 cipher hardware accelerator
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
#include "gd32h7xx.h"
#include "core/crypto.h"
#include "hardware/gd32h7xx/gd32h7xx_crypto.h"
#include "hardware/gd32h7xx/gd32h7xx_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (GD32H7XX_CRYPTO_CIPHER_SUPPORT == ENABLED)


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
 * @brief Perform DES encryption or decryption
 * @param[in] context DES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void desProcessData(DesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   uint32_t temp;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32h7xxCryptoMutex);

   //Configure the data type
   CAU_CTL = CAU_SWAPPING_8BIT;
   //Configure the algorithm and chaining mode
   CAU_CTL |= mode;

   //Set encryption key
   CAU_KEY1H = context->ks[0];
   CAU_KEY1L = context->ks[1];

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      CAU_IV0H = LOAD32BE(iv);
      CAU_IV0L = LOAD32BE(iv + 4);
   }

   //Flush the input and output FIFOs
   CAU_CTL |= CAU_CTL_FFLUSH;
   //Enable the cryptographic processor
   CAU_CTL |= CAU_CTL_CAUEN;

   //Process data
   while(length >= DES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(input);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 4);

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read the output FIFO
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);

      //Next block
      input += DES_BLOCK_SIZE;
      output += DES_BLOCK_SIZE;
      length -= DES_BLOCK_SIZE;
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = CAU_IV0H;
      STORE32BE(temp, iv);
      temp = CAU_IV0L;
      STORE32BE(temp, iv + 4);
   }

   //Disable the cryptographic processor by clearing the CAUEN bit
   CAU_CTL = 0;

   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32h7xxCryptoMutex);
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
   //Perform DES encryption
   desProcessData(context, NULL, input, output, DES_BLOCK_SIZE,
      CAU_MODE_DES_ECB | CAU_ENCRYPT);
}


/**
 * @brief Decrypt a 8-byte block using DES algorithm
 * @param[in] context Pointer to the DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void desDecryptBlock(DesContext *context, const uint8_t *input, uint8_t *output)
{
   //Perform DES decryption
   desProcessData(context, NULL, input, output, DES_BLOCK_SIZE,
      CAU_MODE_DES_ECB | CAU_DECRYPT);
}

#endif
#if (DES3_SUPPORT == ENABLED)

/**
 * @brief Perform Triple DES encryption or decryption
 * @param[in] context Triple DES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void des3ProcessData(Des3Context *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   uint32_t temp;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32h7xxCryptoMutex);

   //Configure the data type
   CAU_CTL = CAU_SWAPPING_8BIT;
   //Configure the algorithm and chaining mode
   CAU_CTL |= mode;

   //Set encryption key
   CAU_KEY1H = context->k1.ks[0];
   CAU_KEY1L = context->k1.ks[1];
   CAU_KEY2H = context->k2.ks[0];
   CAU_KEY2L = context->k2.ks[1];
   CAU_KEY3H = context->k3.ks[0];
   CAU_KEY3L = context->k3.ks[1];

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      CAU_IV0H = LOAD32BE(iv);
      CAU_IV0L = LOAD32BE(iv + 4);
   }

   //Flush the input and output FIFOs
   CAU_CTL |= CAU_CTL_FFLUSH;
   //Enable the cryptographic processor
   CAU_CTL |= CAU_CTL_CAUEN;

   //Process data
   while(length >= DES3_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(input);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 4);

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read the output FIFO
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);

      //Next block
      input += DES3_BLOCK_SIZE;
      output += DES3_BLOCK_SIZE;
      length -= DES3_BLOCK_SIZE;
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = CAU_IV0H;
      STORE32BE(temp, iv);
      temp = CAU_IV0L;
      STORE32BE(temp, iv + 4);
   }

   //Disable the cryptographic processor by clearing the CAUEN bit
   CAU_CTL = 0;

   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32h7xxCryptoMutex);
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
      context->k2.ks[0] = LOAD32BE(key + 0);
      context->k2.ks[1] = LOAD32BE(key + 4);
      context->k3.ks[0] = LOAD32BE(key + 0);
      context->k3.ks[1] = LOAD32BE(key + 4);
   }
   else if(keyLen == 16)
   {
      //If the key length is 128 bits including parity, the first 8 bytes of the
      //encoding represent the key used for the two outer DES operations, and
      //the second 8 bytes represent the key used for the inner DES operation
      context->k1.ks[0] = LOAD32BE(key + 0);
      context->k1.ks[1] = LOAD32BE(key + 4);
      context->k2.ks[0] = LOAD32BE(key + 8);
      context->k2.ks[1] = LOAD32BE(key + 12);
      context->k3.ks[0] = LOAD32BE(key + 0);
      context->k3.ks[1] = LOAD32BE(key + 4);
   }
   else if(keyLen == 24)
   {
      //If the key length is 192 bits including parity, then 3 independent DES
      //keys are represented, in the order in which they are used for encryption
      context->k1.ks[0] = LOAD32BE(key + 0);
      context->k1.ks[1] = LOAD32BE(key + 4);
      context->k2.ks[0] = LOAD32BE(key + 8);
      context->k2.ks[1] = LOAD32BE(key + 12);
      context->k3.ks[0] = LOAD32BE(key + 16);
      context->k3.ks[1] = LOAD32BE(key + 20);
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
   //Perform Triple DES encryption
   des3ProcessData(context, NULL, input, output, DES3_BLOCK_SIZE,
      CAU_MODE_TDES_ECB | CAU_ENCRYPT);
}


/**
 * @brief Decrypt a 8-byte block using Triple DES algorithm
 * @param[in] context Pointer to the Triple DES context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

void des3DecryptBlock(Des3Context *context, const uint8_t *input, uint8_t *output)
{
   //Perform Triple DES decryption
   des3ProcessData(context, NULL, input, output, DES3_BLOCK_SIZE,
      CAU_MODE_TDES_ECB | CAU_DECRYPT);
}

#endif
#if (AES_SUPPORT == ENABLED)

/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 **/

void aesLoadKey(AesContext *context)
{
   uint32_t temp;

   //Read control register
   temp = CAU_CTL & ~CAU_CTL_KEYM;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      CAU_CTL = temp | CAU_KEYSIZE_128BIT;

      //Set the 128-bit encryption key
      CAU_KEY2H = context->ek[0];
      CAU_KEY2L = context->ek[1];
      CAU_KEY3H = context->ek[2];
      CAU_KEY3L = context->ek[3];
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      CAU_CTL = temp | CAU_KEYSIZE_192BIT;

      //Set the 192-bit encryption key
      CAU_KEY1H = context->ek[0];
      CAU_KEY1L = context->ek[1];
      CAU_KEY2H = context->ek[2];
      CAU_KEY2L = context->ek[3];
      CAU_KEY3H = context->ek[4];
      CAU_KEY3L = context->ek[5];
   }
   else
   {
      //14 rounds are required for 256-bit key
      CAU_CTL = temp | CAU_KEYSIZE_256BIT;

      //Set the 256-bit encryption key
      CAU_KEY0H = context->ek[0];
      CAU_KEY0L = context->ek[1];
      CAU_KEY1H = context->ek[2];
      CAU_KEY1L = context->ek[3];
      CAU_KEY2H = context->ek[4];
      CAU_KEY2L = context->ek[5];
      CAU_KEY3H = context->ek[6];
      CAU_KEY3L = context->ek[7];
   }
}


/**
 * @brief Perform AES encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] mode Operation mode
 **/

void aesProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t mode)
{
   uint32_t temp;

   //Acquire exclusive access to the CAU module
   osAcquireMutex(&gd32h7xxCryptoMutex);

   //Configure the data type
   CAU_CTL = CAU_SWAPPING_8BIT;

   //AES-ECB or AES-CBC decryption?
   if((mode & CAU_CTL_CAUDIR) != 0)
   {
      //Select key derivation mode by setting the ALGM bits to '111'
      CAU_CTL |= CAU_MODE_AES_KEY | CAU_CTL_CAUDIR;
      //Set encryption key
      aesLoadKey(context);
      //Write the CAUEN bit to 1
      CAU_CTL |= CAU_CTL_CAUEN;

      //Wait until BUSY returns to 0
      while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
      {
      }

      //The algorithm must be configured once the key has been prepared
      temp = CAU_CTL & ~CAU_CTL_ALGM;
      CAU_CTL = temp | mode;
   }
   else
   {
      //Configure the algorithm and chaining mode
      CAU_CTL |= mode;
      //Set encryption key
      aesLoadKey(context);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      CAU_IV0H = LOAD32BE(iv);
      CAU_IV0L = LOAD32BE(iv + 4);
      CAU_IV1H = LOAD32BE(iv + 8);
      CAU_IV1L = LOAD32BE(iv + 12);
   }

   //Flush the input and output FIFOs
   CAU_CTL |= CAU_CTL_FFLUSH;
   //Enable the cryptographic processor
   CAU_CTL |= CAU_CTL_CAUEN;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(input);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 12);

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read the output FIFO
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 12, temp);

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint32_t buffer[4];

      //Copy partial block
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write input block
      CAU_DI = buffer[0];
      CAU_DI = buffer[1];
      CAU_DI = buffer[2];
      CAU_DI = buffer[3];

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read output block
      buffer[0] = CAU_DO;
      buffer[1] = CAU_DO;
      buffer[2] = CAU_DO;
      buffer[3] = CAU_DO;

      //Copy partial block
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = CAU_IV0H;
      STORE32BE(temp, iv);
      temp = CAU_IV0L;
      STORE32BE(temp, iv + 4);
      temp = CAU_IV1H;
      STORE32BE(temp, iv + 8);
      temp = CAU_IV1L;
      STORE32BE(temp, iv + 12);
   }

   //Disable the cryptographic processor by clearing the CAUEN bit
   CAU_CTL = 0;

   //Release exclusive access to the CAU module
   osReleaseMutex(&gd32h7xxCryptoMutex);
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
   //Perform AES encryption
   aesProcessData(context, NULL, input, output, AES_BLOCK_SIZE,
      CAU_MODE_AES_ECB | CAU_ENCRYPT);
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
      CAU_MODE_AES_ECB | CAU_DECRYPT);
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
         //Encrypt payload data
         desProcessData(context, NULL, p, c, length, CAU_MODE_DES_ECB |
            CAU_ENCRYPT);
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
         //Encrypt payload data
         des3ProcessData(context, NULL, p, c, length, CAU_MODE_TDES_ECB |
            CAU_ENCRYPT);
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
         //Encrypt payload data
         aesProcessData(context, NULL, p, c, length, CAU_MODE_AES_ECB |
            CAU_ENCRYPT);
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
         //Decrypt payload data
         desProcessData(context, NULL, c, p, length, CAU_MODE_DES_ECB |
            CAU_DECRYPT);
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
         //Decrypt payload data
         des3ProcessData(context, NULL, c, p, length, CAU_MODE_TDES_ECB |
            CAU_DECRYPT);
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
         //Decrypt payload data
         aesProcessData(context, NULL, c, p, length, CAU_MODE_AES_ECB |
            CAU_DECRYPT);
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
         //Encrypt payload data
         desProcessData(context, iv, p, c, length, CAU_MODE_DES_CBC |
            CAU_ENCRYPT);
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
         //Encrypt payload data
         des3ProcessData(context, iv, p, c, length, CAU_MODE_TDES_CBC |
            CAU_ENCRYPT);
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
         //Encrypt payload data
         aesProcessData(context, iv, p, c, length, CAU_MODE_AES_CBC |
            CAU_ENCRYPT);
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
         //Decrypt payload data
         desProcessData(context, iv, c, p, length, CAU_MODE_DES_CBC |
            CAU_DECRYPT);
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
         //Decrypt payload data
         des3ProcessData(context, iv, c, p, length, CAU_MODE_TDES_CBC |
            CAU_DECRYPT);
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
         //Decrypt payload data
         aesProcessData(context, iv, c, p, length, CAU_MODE_AES_CBC |
            CAU_DECRYPT);
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
      //Determine the size, in bytes, of the specific part of the block to be
      //incremented
      m = m / 8;

      //AES cipher algorithm?
      if(cipher == AES_CIPHER_ALGO)
      {
         size_t k;
         size_t n;
         uint8_t iv[AES_BLOCK_SIZE];

         //Process plaintext
         while(length > 0)
         {
            //Limit the number of blocks to process at a time
            k = 256 - t[AES_BLOCK_SIZE - 1];
            n = MIN(length, k * AES_BLOCK_SIZE);
            k = (n + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

            //Copy initial counter value
            osMemcpy(iv, t, AES_BLOCK_SIZE);

            //Encrypt payload data
            aesProcessData(context, iv, p, c, n, CAU_MODE_AES_CTR |
               CAU_ENCRYPT);

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
#if (GCM_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

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
 **/

void gcmProcessData(AesContext *context, const uint8_t *iv,
   const uint8_t *a, size_t aLen, const uint8_t *input, uint8_t *output,
   size_t length, uint8_t *t, uint32_t mode)
{
   size_t n;
   uint64_t m;
   uint32_t temp;
   uint32_t h[4];
   uint32_t buffer[4];

   //Acquire exclusive access to the AES module
   osAcquireMutex(&gd32h7xxCryptoMutex);

   //Configure the data type
   CAU_CTL = CAU_SWAPPING_8BIT;

   //Select the GCM chaining mode by programming ALGM bits to '01000'
   temp = CAU_CTL & ~CAU_CTL_ALGM;
   CAU_CTL = temp | CAU_MODE_AES_GCM;

   //Configure GCM_CCMPH bits to '00' to start the GCM prepare phase
   temp = CAU_CTL & ~CAU_CTL_GCM_CCMPH;
   CAU_CTL = temp | CAU_PREPARE_PHASE;

   //Set encryption key
   aesLoadKey(context);

   //Set initialization vector
   CAU_IV0H = LOAD32BE(iv);
   CAU_IV0L = LOAD32BE(iv + 4);
   CAU_IV1H = LOAD32BE(iv + 8);
   CAU_IV1L = 2;

   //Set CAUEN bit to 1 to start the calculation of the HASH key
   CAU_CTL |= CAU_CTL_CAUEN;

   //Wait for the CAUEN bit to be cleared to 0 before moving on to the
   //next phase
   while((CAU_CTL & CAU_CTL_CAUEN) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '01' to start the GCM AAD phase
   temp = CAU_CTL & ~CAU_CTL_GCM_CCMPH;
   CAU_CTL = temp | CAU_AAD_PHASE;

   //Flush the input and output FIFOs
   CAU_CTL |= CAU_CTL_FFLUSH;
   //Set the CAUEN bit to 1 to start accepting data
   CAU_CTL |= CAU_CTL_CAUEN;

   //Process additional authenticated data
   for(n = aLen; n >= AES_BLOCK_SIZE; n -= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(a);
      CAU_DI = __UNALIGNED_UINT32_READ(a + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(a + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(a + 12);

      //Next block
      a += AES_BLOCK_SIZE;
   }

   //Process final block of additional authenticated data
   if(n > 0)
   {
      //Copy partial block
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, a, n);

      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = buffer[0];
      CAU_DI = buffer[1];
      CAU_DI = buffer[2];
      CAU_DI = buffer[3];
   }

   //Once all header data have been supplied, wait until the BUSY bit is
   //cleared
   while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
   {
   }

   //Set the CAUEN bit to 0
   CAU_CTL &= ~CAU_CTL_CAUEN;

   //Configure GCM_CCMPH bits to '10' to start the GCM encryption/decryption
   //phase
   temp = CAU_CTL & ~CAU_CTL_GCM_CCMPH;
   CAU_CTL = temp | CAU_ENCRYPT_DECRYPT_PHASE;

   //Select the algorithm direction by using the ALGODIR bit
   temp = CAU_CTL & ~CAU_DECRYPT;
   CAU_CTL |= mode;

   //Set the CAUEN bit to 1 to start accepting data
   CAU_CTL |= CAU_CTL_CAUEN;

   //Process data
   for(n = length; n >= AES_BLOCK_SIZE; n -= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(input);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 12);

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read the output FIFO
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 12, temp);

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(n > 0)
   {
      //Copy partial block
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, n);

      //Workaround for GCM encryption mode
      if((mode & CAU_CTL_CAUDIR) == 0)
      {
         //Wait until the BUSY bit is cleared
         while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
         {
         }

         //Save the current GHASH value
         h[0] = CAU_GCMCTXSx(0);
         h[1] = CAU_GCMCTXSx(1);
         h[2] = CAU_GCMCTXSx(2);
         h[3] = CAU_GCMCTXSx(3);
      }

      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = buffer[0];
      CAU_DI = buffer[1];
      CAU_DI = buffer[2];
      CAU_DI = buffer[3];

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read the output FIFO
      buffer[0] = CAU_DO;
      buffer[1] = CAU_DO;
      buffer[2] = CAU_DO;
      buffer[3] = CAU_DO;

      //Copy partial block
      osMemcpy(output, buffer, n);

      //Workaround for GCM encryption mode
      if((mode & CAU_CTL_CAUDIR) == 0)
      {
         //Pad the final ciphertext block with zeroes
         osMemset((uint8_t *) buffer + n, 0, AES_BLOCK_SIZE - n);

         //Wait until the BUSY bit is cleared
         while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
         {
         }

         //Switch to decryption mode
         CAU_CTL |= CAU_DECRYPT;

         //Restore the previous GHASH value
         CAU_GCMCTXSx(0) = h[0];
         CAU_GCMCTXSx(1) = h[1];
         CAU_GCMCTXSx(2) = h[2];
         CAU_GCMCTXSx(3) = h[3];

         //Wait for the input FIFO to be ready to accept data
         while((CAU_STAT0 & CAU_STAT0_INF) == 0)
         {
         }

         //Write the input FIFO
         CAU_DI = buffer[0];
         CAU_DI = buffer[1];
         CAU_DI = buffer[2];
         CAU_DI = buffer[3];

         //Wait until the OFNE flag is set to 1 in the CRYP_SR register
         while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
         {
         }

         //Read the output FIFO and discard the data
         buffer[0] = CAU_DO;
         buffer[1] = CAU_DO;
         buffer[2] = CAU_DO;
         buffer[3] = CAU_DO;
      }
   }

   //Once all payload data have been supplied, wait until the BUSY flag is
   //cleared
   while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '11' to start the GCM tag phase
   temp = CAU_CTL & ~CAU_CTL_GCM_CCMPH;
   CAU_CTL = temp | CAU_TAG_PHASE;

   //Write the input into the CRYP_DIN register 4 times. The input must
   //contain the number of bits in the header (64 bits) concatenated with
   //the number of bits in the payload (64 bits)
   m = aLen * 8;
   CAU_DI = htobe32(m >> 32);
   CAU_DI = htobe32(m);
   m = length * 8;
   CAU_DI = htobe32(m >> 32);
   CAU_DI = htobe32(m);

   //Wait until the OFNE flag is set to 1 in the CRYP_SR register
   while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
   {
   }

   //Read the CRYP_DOUT register 4 times. The output corresponds to the
   //authentication tag
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t, temp);
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t + 4, temp);
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t + 8, temp);
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t + 12, temp);

   //Disable the cryptographic processor by clearing the CAUEN bit
   CAU_CTL = 0;

   //Release exclusive access to the AES module
   osReleaseMutex(&gd32h7xxCryptoMutex);
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
   //The CAU module only supports AES cipher algorithm
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
   gcmProcessData(context->cipherContext, iv, a, aLen, p, c, length,
      authTag, 0);

   //Copy the resulting authentication tag
   osMemcpy(t, authTag, tLen);

   //Successful processing
   return NO_ERROR;
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
   gcmProcessData(context->cipherContext, iv, a, aLen, c, p, length,
      authTag, CAU_DECRYPT);

   //The calculated tag is bitwise compared to the received tag
   for(mask = 0, i = 0; i < tLen; i++)
   {
      mask |= authTag[i] ^ t[i];
   }

   //The message is authenticated if and only if the tags match
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (CCM_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)

/**
 * @brief Perform AES-CCM encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in] b0 Pointer to the B0 block
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[out] t Authentication tag
 * @param[in] mode Operation mode
 **/

void ccmProcessData(AesContext *context, const uint8_t *b0, const uint8_t *a,
   size_t aLen, const uint8_t *input, uint8_t *output, size_t length,
   uint8_t *t, uint32_t mode)
{
   size_t n;
   size_t qLen;
   uint32_t temp;
   uint32_t y[4];
   uint8_t buffer[16];

   //Acquire exclusive access to the AES module
   osAcquireMutex(&gd32h7xxCryptoMutex);

   //Configure the data type
   CAU_CTL = CAU_SWAPPING_8BIT;

   //Select the CCM chaining mode by programming ALGM bits to '01001'
   temp = CAU_CTL & ~CAU_CTL_ALGM;
   CAU_CTL = temp | CAU_MODE_AES_CCM;

   //Configure GCM_CCMPH bits to '00' to start the CCM prepare phase
   temp = CAU_CTL & ~CAU_CTL_GCM_CCMPH;
   CAU_CTL = temp | CAU_PREPARE_PHASE;

   //Set encryption key
   aesLoadKey(context);

   //Retrieve the octet length of Q
   qLen = (b0[0] & 0x07) + 1;

   //Format CTR(1)
   osMemcpy(buffer, b0, 16 - qLen);
   osMemset(buffer + 16 - qLen, 0, qLen);

   //Set the leading octet
   buffer[0] = (uint8_t) (qLen - 1);
   //Set counter value
   buffer[15] = 1;

   //Initialize CRYP_IVRx registers with CTR(1)
   CAU_IV0H = LOAD32BE(buffer);
   CAU_IV0L = LOAD32BE(buffer + 4);
   CAU_IV1H = LOAD32BE(buffer + 8);
   CAU_IV1L = LOAD32BE(buffer + 12);

   //Set the CAUEN bit to 1 to start accepting data
   CAU_CTL |= CAU_CTL_CAUEN;

   //Write the B0 packet into CRYP_DIN register
   CAU_DI = __UNALIGNED_UINT32_READ(b0);
   CAU_DI = __UNALIGNED_UINT32_READ(b0 + 4);
   CAU_DI = __UNALIGNED_UINT32_READ(b0 + 8);
   CAU_DI = __UNALIGNED_UINT32_READ(b0 + 12);

   //Wait for the CAUEN bit to be cleared to 0 by the cryptographic processor
   //before moving on to the next phase
   while((CAU_CTL & CAU_CTL_CAUEN) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '01' to start the CCM AAD phase
   temp = CAU_CTL & ~CAU_CTL_GCM_CCMPH;
   CAU_CTL = temp | CAU_AAD_PHASE;

   //Flush the input and output FIFOs
   CAU_CTL |= CAU_CTL_FFLUSH;
   //Set the CAUEN bit to 1 to start accepting data
   CAU_CTL |= CAU_CTL_CAUEN;

   //The header phase can be skipped if there is no associated data
   if(aLen > 0)
   {
      //The first block of the associated data (B1) must be formatted by
      //software, with the associated data length
      osMemset(buffer, 0, 16);

      //Check the length of the associated data string
      if(aLen < 0xFF00)
      {
         //The length is encoded as 2 octets
         STORE16BE(aLen, buffer);

         //Number of bytes to copy
         n = MIN(aLen, 16 - 2);
         //Concatenate the associated data A
         osMemcpy(buffer + 2, a, n);
      }
      else
      {
         //The length is encoded as 6 octets
         buffer[0] = 0xFF;
         buffer[1] = 0xFE;

         //MSB is stored first
         STORE32BE(aLen, buffer + 2);

         //Number of bytes to copy
         n = MIN(aLen, 16 - 6);
         //Concatenate the associated data A
         osMemcpy(buffer + 6, a, n);
      }

      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(buffer);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 12);

      //Number of remaining data bytes
      aLen -= n;
      a += n;
   }

   //Process additional authenticated data
   while(aLen >= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(a);
      CAU_DI = __UNALIGNED_UINT32_READ(a + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(a + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(a + 12);

      //Next block
      a += AES_BLOCK_SIZE;
      aLen -= AES_BLOCK_SIZE;
   }

   //Process final block of additional authenticated data
   if(aLen > 0)
   {
      //If the AAD size in the last block is inferior to 128 bits, pad the
      //remainder of the block with zeros
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, a, aLen);

      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(buffer);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 12);
   }

   //Once all header data have been supplied, wait until the BUSY bit is
   //cleared
   while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
   {
   }

   //Set the CAUEN bit to 0
   CAU_CTL &= ~CAU_CTL_CAUEN;

   //Configure GCM_CCMPH bits to '10' to start the CCM encryption/decryption
   //phase
   temp = CAU_CTL & ~CAU_CTL_GCM_CCMPH;
   CAU_CTL = temp | CAU_ENCRYPT_DECRYPT_PHASE;

   //Select the algorithm direction by using the ALGODIR bit
   temp = CAU_CTL & ~CAU_DECRYPT;
   CAU_CTL |= mode;

   //Set the CAUEN bit to 1 to start accepting data
   CAU_CTL |= CAU_CTL_CAUEN;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(input);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(input + 12);

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read the output FIFO
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(output + 12, temp);

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      //If it is the last block and the plaintext (encryption) or ciphertext
      //(decryption) size in the block is inferior to 128 bits, pad the
      //remainder of the block with zeros
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Workaround for CCM decryption mode
      if((mode & CAU_CTL_CAUDIR) != 0)
      {
         //Wait until the BUSY bit is cleared
         while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
         {
         }

         //Save the current value of Y
         y[0] = CAU_GCMCCMCTXSx(0);
         y[1] = CAU_GCMCCMCTXSx(1);
         y[2] = CAU_GCMCCMCTXSx(2);
         y[3] = CAU_GCMCCMCTXSx(3);
      }

      //Wait for the input FIFO to be ready to accept data
      while((CAU_STAT0 & CAU_STAT0_INF) == 0)
      {
      }

      //Write the input FIFO
      CAU_DI = __UNALIGNED_UINT32_READ(buffer);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 4);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 8);
      CAU_DI = __UNALIGNED_UINT32_READ(buffer + 12);

      //Wait for the output to be ready
      while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
      {
      }

      //Read the output FIFO
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(buffer, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(buffer + 4, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(buffer + 8, temp);
      temp = CAU_DO;
      __UNALIGNED_UINT32_WRITE(buffer + 12, temp);

      //Discard the bits that are not part of the payload when the last block
      //size is less than 16 bytes
      osMemcpy(output, buffer, length);

      //Workaround for CCM decryption mode
      if((mode & CAU_CTL_CAUDIR) != 0)
      {
         //Pad the final plaintext block with zeroes
         osMemset(buffer + length, 0, AES_BLOCK_SIZE - length);

         //Wait until the BUSY bit is cleared
         while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
         {
         }

         //Switch to encryption mode
         CAU_CTL &= ~CAU_DECRYPT;

         //Restore the previous value of Y
         CAU_GCMCCMCTXSx(0) = y[0];
         CAU_GCMCCMCTXSx(1) = y[1];
         CAU_GCMCCMCTXSx(2) = y[2];
         CAU_GCMCCMCTXSx(3) = y[3];

         //Wait for the input FIFO to be ready to accept data
         while((CAU_STAT0 & CAU_STAT0_INF) == 0)
         {
         }

         //Write the input FIFO
         CAU_DI = __UNALIGNED_UINT32_READ(buffer);
         CAU_DI = __UNALIGNED_UINT32_READ(buffer + 4);
         CAU_DI = __UNALIGNED_UINT32_READ(buffer + 8);
         CAU_DI = __UNALIGNED_UINT32_READ(buffer + 12);

         //Wait for the output to be ready
         while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
         {
         }

         //Read the output FIFO and discard the data
         temp = CAU_DO;
         temp = CAU_DO;
         temp = CAU_DO;
         temp = CAU_DO;
      }
   }

   //Once all payload data have been supplied, wait until the BUSY flag is
   //cleared
   while((CAU_STAT0 & CAU_STAT0_BUSY) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '11' to start the CCM tag phase
   temp = CAU_CTL & ~(CAU_CTL_GCM_CCMPH | CAU_DECRYPT);
   CAU_CTL = temp | CAU_TAG_PHASE;

   //Format CTR(0)
   osMemcpy(buffer, b0, 16 - qLen);
   osMemset(buffer + 16 - qLen, 0, qLen);

   //Set the leading octet
   buffer[0] = (uint8_t) (qLen - 1);

   //Load in CRYP_DIN the CTR(0) information
   CAU_DI = __UNALIGNED_UINT32_READ(buffer);
   CAU_DI = __UNALIGNED_UINT32_READ(buffer + 4);
   CAU_DI = __UNALIGNED_UINT32_READ(buffer + 8);
   CAU_DI = __UNALIGNED_UINT32_READ(buffer + 12);

   //Wait until the OFNE flag is set to 1 in the CRYP_SR register
   while((CAU_STAT0 & CAU_STAT0_ONE) == 0)
   {
   }

   //Read the CRYP_DOUT register 4 times. The output corresponds to the
   //authentication tag
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t, temp);
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t + 4, temp);
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t + 8, temp);
   temp = CAU_DO;
   __UNALIGNED_UINT32_WRITE(t + 12, temp);

   //Disable the cryptographic processor by clearing the CAUEN bit
   CAU_CTL = 0;

   //Release exclusive access to the AES module
   osReleaseMutex(&gd32h7xxCryptoMutex);
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
   uint8_t b0[16];
   uint8_t authTag[16];

   //Check parameters
   if(cipher == NULL || context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The CAU module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Format first block B(0)
   error = ccmFormatBlock0(length, n, nLen, aLen, tLen, b0);
   //Invalid parameters?
   if(error)
      return error;

   //Perform AES-CCM encryption
   ccmProcessData(context, b0, a, aLen, p, c, length, authTag, 0);

   //Copy the resulting authentication tag
   osMemcpy(t, authTag, tLen);

   //Successful processing
   return NO_ERROR;
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
   uint8_t mask;
   uint8_t b0[16];
   uint8_t authTag[16];

   //Check parameters
   if(cipher == NULL || context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The CAU module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Format first block B(0)
   error = ccmFormatBlock0(length, n, nLen, aLen, tLen, b0);
   //Invalid parameters?
   if(error)
      return error;

   //Perform AES-CCM decryption
   ccmProcessData(context, b0, a, aLen, c, p, length, authTag, CAU_DECRYPT);

   //The calculated tag is bitwise compared to the received tag
   for(mask = 0, i = 0; i < tLen; i++)
   {
      mask |= authTag[i] ^ t[i];
   }

   //The message is authenticated if and only if the tags match
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif
