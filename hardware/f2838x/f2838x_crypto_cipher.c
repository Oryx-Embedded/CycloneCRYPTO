/**
 * @file f2838x_crypto_cipher.c
 * @brief TMS320F2838xD cipher hardware accelerator
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
#include <stdint.h>
#include <stdbool.h>
#include "inc/hw_types.h"
#include "inc/hw_memmap.h"
#include "inc/hw_aes.h"
#include "driverlib_cm/aes.h"
#include "core/crypto.h"
#include "hardware/f2838x/f2838x_crypto.h"
#include "hardware/f2838x/f2838x_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (F2838X_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief Set AES operation mode
 * @param[in] mode Mode of operation
 **/

void aesSetMode(uint32_t mode)
{
   //Perform a software reset
   AES_SYSCONFIG_R |= AES_SYSCONFIG_SOFTRESET;

   //Wait for the reset to complete
   while((AES_SYSSTATUS_R & AES_SYSSTATUS_RESETDONE) == 0)
   {
   }

   //Backup the save context field before updating the register
   if((AES_CTRL_R & AES_CTRL_SAVE_CONTEXT) != 0)
   {
      mode |= AES_CTRL_SAVE_CONTEXT;
   }

   //Write control register
   AES_CTRL_R = mode;
}


/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 **/

void aesLoadKey(AesContext *context)
{
   uint32_t temp;

   //Read control register
   temp = AES_CTRL_R & ~AES_CTRL_KEY_SIZE_M;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      AES_CTRL_R = temp | AES_KEY_SIZE_128BIT;

      //Set the 128-bit encryption key
      AES_KEY1_0_R = context->ek[0];
      AES_KEY1_1_R = context->ek[1];
      AES_KEY1_2_R = context->ek[2];
      AES_KEY1_3_R = context->ek[3];
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      AES_CTRL_R = temp | AES_KEY_SIZE_192BIT;

      //Set the 192-bit encryption key
      AES_KEY1_0_R = context->ek[0];
      AES_KEY1_1_R = context->ek[1];
      AES_KEY1_2_R = context->ek[2];
      AES_KEY1_3_R = context->ek[3];
      AES_KEY1_4_R = context->ek[4];
      AES_KEY1_5_R = context->ek[5];
   }
   else
   {
      //14 rounds are required for 256-bit key
      AES_CTRL_R = temp | AES_KEY_SIZE_256BIT;

      //Set the 256-bit encryption key
      AES_KEY1_0_R = context->ek[0];
      AES_KEY1_1_R = context->ek[1];
      AES_KEY1_2_R = context->ek[2];
      AES_KEY1_3_R = context->ek[3];
      AES_KEY1_4_R = context->ek[4];
      AES_KEY1_5_R = context->ek[5];
      AES_KEY1_6_R = context->ek[6];
      AES_KEY1_7_R = context->ek[7];
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

   //Acquire exclusive access to the AES module
   osAcquireMutex(&f2838xCryptoMutex);

   //Set operation mode
   aesSetMode(mode);
   //Set encryption key
   aesLoadKey(context);

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      AES_IV_IN_OUT_0_R = LOAD32LE(iv);
      AES_IV_IN_OUT_1_R = LOAD32LE(iv + 4);
      AES_IV_IN_OUT_2_R = LOAD32LE(iv + 8);
      AES_IV_IN_OUT_3_R = LOAD32LE(iv + 12);
   }

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Wait for the AES engine to be ready to accept data
      while((AES_CTRL_R & AES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      AES_DATA_IN_OUT_3_R = LOAD32LE(input);
      AES_DATA_IN_OUT_2_R = LOAD32LE(input + 4);
      AES_DATA_IN_OUT_1_R = LOAD32LE(input + 8);
      AES_DATA_IN_OUT_0_R = LOAD32LE(input + 12);

      //Wait for the output to be ready
      while((AES_CTRL_R & AES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      temp = AES_DATA_IN_OUT_3_R;
      STORE32LE(temp, output);
      temp = AES_DATA_IN_OUT_2_R;
      STORE32LE(temp, output + 4);
      temp = AES_DATA_IN_OUT_1_R;
      STORE32LE(temp, output + 8);
      temp = AES_DATA_IN_OUT_0_R;
      STORE32LE(temp, output + 12);

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

      //Wait for the AES engine to be ready to accept data
      while((AES_CTRL_R & AES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      AES_DATA_IN_OUT_3_R = buffer[0];
      AES_DATA_IN_OUT_2_R = buffer[1];
      AES_DATA_IN_OUT_1_R = buffer[2];
      AES_DATA_IN_OUT_0_R = buffer[3];

      //Wait for the output to be ready
      while((AES_CTRL_R & AES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      buffer[0] = AES_DATA_IN_OUT_3_R;
      buffer[1] = AES_DATA_IN_OUT_2_R;
      buffer[2] = AES_DATA_IN_OUT_1_R;
      buffer[3] = AES_DATA_IN_OUT_0_R;

      //Copy partial block
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = AES_IV_IN_OUT_0_R;
      STORE32LE(temp, iv);
      temp = AES_IV_IN_OUT_1_R;
      STORE32LE(temp, iv + 4);
      temp = AES_IV_IN_OUT_2_R;
      STORE32LE(temp, iv + 8);
      temp = AES_IV_IN_OUT_3_R;
      STORE32LE(temp, iv + 12);
   }

   //Release exclusive access to the AES module
   osReleaseMutex(&f2838xCryptoMutex);
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

   //Copy the original key
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
      AES_DIRECTION_ENCRYPT | AES_OPMODE_ECB);
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
      AES_DIRECTION_DECRYPT | AES_OPMODE_ECB);
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
         aesProcessData(context, NULL, p, c, length, AES_DIRECTION_ENCRYPT |
            AES_OPMODE_ECB);
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
         aesProcessData(context, NULL, c, p, length, AES_DIRECTION_DECRYPT |
            AES_OPMODE_ECB);
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
         aesProcessData(context, iv, p, c, length, AES_DIRECTION_ENCRYPT |
            AES_OPMODE_CBC);
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
         aesProcessData(context, iv, c, p, length, AES_DIRECTION_DECRYPT |
            AES_OPMODE_CBC);
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
#if (CFB_SUPPORT == ENABLED)

/**
 * @brief CFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t cfbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            aesProcessData(context, iv, p, c, length, AES_DIRECTION_ENCRYPT |
               AES_OPMODE_CFB);
         }
         else
         {
            //No data to process
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
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each plaintext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute C(j) = P(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               c[i] = p[i] ^ o[i];
            }

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, c, s);

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
 * @brief CFB decryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t cfbDecrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *c, uint8_t *p, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //AES cipher algorithm?
   if(cipher == AES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (AES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            aesProcessData(context, iv, c, p, length, AES_DIRECTION_DECRYPT |
               AES_OPMODE_CFB);
         }
         else
         {
            //No data to process
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
      if((s % 8) == 0 && s >= 1 && s <= (cipher->blockSize * 8))
      {
         size_t i;
         size_t n;
         uint8_t o[16];

         //Determine the size, in bytes, of the plaintext and ciphertext segments
         s = s / 8;

         //Process each ciphertext segment
         while(length > 0)
         {
            //Compute the number of bytes to process at a time
            n = MIN(length, s);

            //Compute O(j) = CIPH(I(j))
            cipher->encryptBlock(context, iv, o);

            //Compute I(j+1) = LSB(I(j)) | C(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, c, s);

            //Compute P(j) = C(j) XOR MSB(O(j))
            for(i = 0; i < n; i++)
            {
               p[i] = c[i] ^ o[i];
            }

            //Next block
            c += n;
            p += n;
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
            aesProcessData(context, iv, p, c, n, AES_DIRECTION_ENCRYPT |
               AES_OPMODE_CTR | AES_CTR_WIDTH_128BIT);

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
 **/

void gcmProcessData(AesContext *context, const uint8_t *iv,
   const uint8_t *a, size_t aLen, const uint8_t *input, uint8_t *output,
   size_t length, uint8_t *t, uint32_t mode)
{
   uint32_t temp;
   uint32_t buffer[4];

   //Acquire exclusive access to the AES module
   osAcquireMutex(&f2838xCryptoMutex);

   //Check parameters
   if(aLen > 0 || length > 0)
   {
      //Set GCM operation mode
      aesSetMode(AES_OPMODE_GCM_HY0CALC | mode);
      //Set encryption key
      aesLoadKey(context);

      //When the length of the IV is 96 bits, the padding string is appended to
      //the IV to form the pre-counter block
      AES_IV_IN_OUT_0_R = LOAD32LE(iv);
      AES_IV_IN_OUT_1_R = LOAD32LE(iv + 4);
      AES_IV_IN_OUT_2_R = LOAD32LE(iv + 8);
      AES_IV_IN_OUT_3_R = BETOH32(1);

      //Set data length
      AES_C_LENGTH_0_R = length;
      AES_C_LENGTH_1_R = 0;

      //Set additional authenticated data length
      AES_AUTH_LENGTH_R = aLen;

      //Process additional authenticated data
      while(aLen >= AES_BLOCK_SIZE)
      {
         //Wait for the AES engine to be ready to accept data
         while((AES_CTRL_R & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write block
         AES_DATA_IN_OUT_3_R = LOAD32LE(a);
         AES_DATA_IN_OUT_2_R = LOAD32LE(a + 4);
         AES_DATA_IN_OUT_1_R = LOAD32LE(a + 8);
         AES_DATA_IN_OUT_0_R = LOAD32LE(a + 12);

         //Next block
         a += AES_BLOCK_SIZE;
         aLen -= AES_BLOCK_SIZE;
      }

      //Process final block of additional authenticated data
      if(aLen > 0)
      {
         //Copy partial block
         osMemset(buffer, 0, AES_BLOCK_SIZE);
         osMemcpy(buffer, a, aLen);

         //Wait for the AES engine to be ready to accept data
         while((AES_CTRL_R & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write block
         AES_DATA_IN_OUT_3_R = buffer[0];
         AES_DATA_IN_OUT_2_R = buffer[1];
         AES_DATA_IN_OUT_1_R = buffer[2];
         AES_DATA_IN_OUT_0_R = buffer[3];
      }

      //Process data
      while(length >= AES_BLOCK_SIZE)
      {
         //Wait for the AES engine to be ready to accept data
         while((AES_CTRL_R & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write input block
         AES_DATA_IN_OUT_3_R = LOAD32LE(input);
         AES_DATA_IN_OUT_2_R = LOAD32LE(input + 4);
         AES_DATA_IN_OUT_1_R = LOAD32LE(input + 8);
         AES_DATA_IN_OUT_0_R = LOAD32LE(input + 12);

         //Wait for the output to be ready
         while((AES_CTRL_R & AES_CTRL_OUTPUT_READY) == 0)
         {
         }

         //Read output block
         temp = AES_DATA_IN_OUT_3_R;
         STORE32LE(temp, output);
         temp = AES_DATA_IN_OUT_2_R;
         STORE32LE(temp, output + 4);
         temp = AES_DATA_IN_OUT_1_R;
         STORE32LE(temp, output + 8);
         temp = AES_DATA_IN_OUT_0_R;
         STORE32LE(temp, output + 12);

         //Next block
         input += AES_BLOCK_SIZE;
         output += AES_BLOCK_SIZE;
         length -= AES_BLOCK_SIZE;
      }

      //Process final block of data
      if(length > 0)
      {
         //Copy partial block
         osMemset(buffer, 0, AES_BLOCK_SIZE);
         osMemcpy(buffer, input, length);

         //Wait for the AES engine to be ready to accept data
         while((AES_CTRL_R & AES_CTRL_INPUT_READY) == 0)
         {
         }

         //Write input block
         AES_DATA_IN_OUT_3_R = buffer[0];
         AES_DATA_IN_OUT_2_R = buffer[1];
         AES_DATA_IN_OUT_1_R = buffer[2];
         AES_DATA_IN_OUT_0_R = buffer[3];

         //Wait for the output to be ready
         while((AES_CTRL_R & AES_CTRL_OUTPUT_READY) == 0)
         {
         }

         //Read output block
         buffer[0] = AES_DATA_IN_OUT_3_R;
         buffer[1] = AES_DATA_IN_OUT_2_R;
         buffer[2] = AES_DATA_IN_OUT_1_R;
         buffer[3] = AES_DATA_IN_OUT_0_R;

         //Copy partial block
         osMemcpy(output, buffer, length);
      }

      //Wait for the output context to be ready
      while((AES_CTRL_R & AES_CTRL_SVCTXTRDY) == 0)
      {
      }

      //Read the authentication tag
      temp = AES_TAG_OUT_0_R;
      STORE32LE(temp, t);
      temp = AES_TAG_OUT_1_R;
      STORE32LE(temp, t + 4);
      temp = AES_TAG_OUT_2_R;
      STORE32LE(temp, t + 8);
      temp = AES_TAG_OUT_3_R;
      STORE32LE(temp, t + 12);
   }
   else
   {
      //Set CTR operation mode
      aesSetMode(AES_DIRECTION_ENCRYPT | AES_OPMODE_CTR |
         AES_CTR_WIDTH_32BIT);

      //Set encryption key
      aesLoadKey(context);

      //When the length of the IV is 96 bits, the padding string is appended to
      //the IV to form the pre-counter block
      AES_IV_IN_OUT_0_R = LOAD32LE(iv);
      AES_IV_IN_OUT_1_R = LOAD32LE(iv + 4);
      AES_IV_IN_OUT_2_R = LOAD32LE(iv + 8);
      AES_IV_IN_OUT_3_R = BETOH32(1);

      //Wait for the AES engine to be ready to accept data
      while((AES_CTRL_R & AES_CTRL_INPUT_READY) == 0)
      {
      }

      //Write input block
      AES_DATA_IN_OUT_3_R = 0;
      AES_DATA_IN_OUT_2_R = 0;
      AES_DATA_IN_OUT_1_R = 0;
      AES_DATA_IN_OUT_0_R = 0;

      //Wait for the output to be ready
      while((AES_CTRL_R & AES_CTRL_OUTPUT_READY) == 0)
      {
      }

      //Read output block
      temp = AES_DATA_IN_OUT_3_R;
      STORE32LE(temp, t);
      temp = AES_DATA_IN_OUT_2_R;
      STORE32LE(temp, t + 4);
      temp = AES_DATA_IN_OUT_1_R;
      STORE32LE(temp, t + 8);
      temp = AES_DATA_IN_OUT_0_R;
      STORE32LE(temp, t + 12);
   }

   //Release exclusive access to the AES module
   osReleaseMutex(&f2838xCryptoMutex);
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
   gcmProcessData(context->cipherContext, iv, a, aLen, p, c, length, authTag,
      AES_DIRECTION_ENCRYPT);

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
   gcmProcessData(context->cipherContext, iv, a, aLen, c, p, length, authTag,
      AES_DIRECTION_DECRYPT);

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
