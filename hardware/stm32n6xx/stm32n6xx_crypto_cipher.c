/**
 * @file stm32n6xx_crypto_cipher.c
 * @brief STM32N6 cipher hardware accelerator
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
#include "stm32n6xx.h"
#include "stm32n6xx_hal.h"
#include "core/crypto.h"
#include "hardware/stm32n6xx/stm32n6xx_crypto.h"
#include "hardware/stm32n6xx/stm32n6xx_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32N6XX_CRYPTO_CIPHER_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)


/**
 * @brief CRYP module initialization
 * @return Error code
 **/

error_t crypInit(void)
{
   //Enable CRYP peripheral clock
   __HAL_RCC_CRYP_CLK_ENABLE();

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Load AES key
 * @param[in] context AES algorithm context
 **/

void aesLoadKey(AesContext *context)
{
   uint32_t temp;

   //Read control register
   temp = CRYP->CR & ~CRYP_CR_KEYSIZE;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      CRYP->CR = temp | CRYP_CR_KEYSIZE_128B;

      //Set the 128-bit encryption key
      CRYP->K2LR = context->ek[0];
      CRYP->K2RR = context->ek[1];
      CRYP->K3LR = context->ek[2];
      CRYP->K3RR = context->ek[3];
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      CRYP->CR = temp | CRYP_CR_KEYSIZE_192B;

      //Set the 192-bit encryption key
      CRYP->K1LR = context->ek[0];
      CRYP->K1RR = context->ek[1];
      CRYP->K2LR = context->ek[2];
      CRYP->K2RR = context->ek[3];
      CRYP->K3LR = context->ek[4];
      CRYP->K3RR = context->ek[5];
   }
   else
   {
      //14 rounds are required for 256-bit key
      CRYP->CR = temp | CRYP_CR_KEYSIZE_256B;

      //Set the 256-bit encryption key
      CRYP->K0LR = context->ek[0];
      CRYP->K0RR = context->ek[1];
      CRYP->K1LR = context->ek[2];
      CRYP->K1RR = context->ek[3];
      CRYP->K2LR = context->ek[4];
      CRYP->K2RR = context->ek[5];
      CRYP->K3LR = context->ek[6];
      CRYP->K3RR = context->ek[7];
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

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32n6xxCryptoMutex);

   //Configure the data type
   CRYP->CR = CRYP_CR_DATATYPE_8B;

   //AES-ECB or AES-CBC decryption?
   if((mode & CRYP_CR_ALGODIR) != 0)
   {
      //Configure the key preparation mode by setting the ALGOMODE bits to '111'
      CRYP->CR |= CRYP_CR_ALGOMODE_AES_KEY;
      //Set encryption key
      aesLoadKey(context);
      //Write the CRYPEN bit to 1
      CRYP->CR |= CRYP_CR_CRYPEN;

      //Wait until BUSY returns to 0
      while((CRYP->SR & CRYP_SR_BUSY) != 0)
      {
      }

      //The algorithm must be configured once the key has been prepared
      temp = CRYP->CR & ~CRYP_CR_ALGOMODE;
      CRYP->CR = temp | mode;
   }
   else
   {
      //Configure the algorithm and chaining mode
      CRYP->CR |= mode;
      //Set encryption key
      aesLoadKey(context);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      CRYP->IV0LR = LOAD32BE(iv);
      CRYP->IV0RR = LOAD32BE(iv + 4);
      CRYP->IV1LR = LOAD32BE(iv + 8);
      CRYP->IV1RR = LOAD32BE(iv + 12);
   }

   //Flush the input and output FIFOs
   CRYP->CR |= CRYP_CR_FFLUSH;
   //Enable the cryptographic processor
   CRYP->CR |= CRYP_CR_CRYPEN;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(input);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 12);

      //Wait for the output to be ready
      while((CRYP->SR & CRYP_SR_OFNE) == 0)
      {
      }

      //Read the output FIFO
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = CRYP->DOUT;
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
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write input block
      CRYP->DIN = buffer[0];
      CRYP->DIN = buffer[1];
      CRYP->DIN = buffer[2];
      CRYP->DIN = buffer[3];

      //Wait for the output to be ready
      while((CRYP->SR & CRYP_SR_OFNE) == 0)
      {
      }

      //Read output block
      buffer[0] = CRYP->DOUT;
      buffer[1] = CRYP->DOUT;
      buffer[2] = CRYP->DOUT;
      buffer[3] = CRYP->DOUT;

      //Copy partial block
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = CRYP->IV0LR;
      STORE32BE(temp, iv);
      temp = CRYP->IV0RR;
      STORE32BE(temp, iv + 4);
      temp = CRYP->IV1LR;
      STORE32BE(temp, iv + 8);
      temp = CRYP->IV1RR;
      STORE32BE(temp, iv + 12);
   }

   //Disable the cryptographic processor by clearing the CRYPEN bit
   CRYP->CR = 0;

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32n6xxCryptoMutex);
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
      CRYP_CR_ALGOMODE_AES_ECB);
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
      CRYP_CR_ALGOMODE_AES_ECB | CRYP_CR_ALGODIR);
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
         aesProcessData(context, NULL, p, c, length, CRYP_CR_ALGOMODE_AES_ECB);
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
         aesProcessData(context, NULL, c, p, length, CRYP_CR_ALGOMODE_AES_ECB |
            CRYP_CR_ALGODIR);
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
         aesProcessData(context, iv, p, c, length, CRYP_CR_ALGOMODE_AES_CBC);
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
         aesProcessData(context, iv, c, p, length, CRYP_CR_ALGOMODE_AES_CBC |
            CRYP_CR_ALGODIR);
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
            aesProcessData(context, iv, p, c, n, CRYP_CR_ALGOMODE_AES_CTR);

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
   size_t n;
   uint64_t m;
   uint32_t temp;
   uint32_t buffer[4];

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32n6xxCryptoMutex);

   //Configure the data type
   CRYP->CR = CRYP_CR_DATATYPE_8B;

   //Select the GCM chaining mode by programming ALGOMODE bits to '01000'
   temp = CRYP->CR & ~CRYP_CR_ALGOMODE;
   CRYP->CR = temp | CRYP_CR_ALGOMODE_AES_GCM;

   //Configure GCM_CCMPH bits to '00' to start the GCM init phase
   temp = CRYP->CR & ~CRYP_CR_GCM_CCMPH;
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_INIT;

   //Set encryption key
   aesLoadKey(context);

   //Set initialization vector
   CRYP->IV0LR = LOAD32BE(iv);
   CRYP->IV0RR = LOAD32BE(iv + 4);
   CRYP->IV1LR = LOAD32BE(iv + 8);
   CRYP->IV1RR = 2;

   //Set CRYPEN bit to 1 to start the calculation of the HASH key
   CRYP->CR |= CRYP_CR_CRYPEN;

   //Wait for the CRYPEN bit to be cleared to 0 before moving on to the
   //next phase
   while((CRYP->CR & CRYP_CR_CRYPEN) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '01' to start GCM header phase
   temp = CRYP->CR & ~CRYP_CR_GCM_CCMPH;
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_HEADER;

   //Flush the input and output FIFOs
   CRYP->CR |= CRYP_CR_FFLUSH;
   //Set the CRYPEN bit to 1 to start accepting data
   CRYP->CR |= CRYP_CR_CRYPEN;

   //Process additional authenticated data
   for(n = aLen; n >= AES_BLOCK_SIZE; n -= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(a);
      CRYP->DIN = __UNALIGNED_UINT32_READ(a + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(a + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(a + 12);

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
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = buffer[0];
      CRYP->DIN = buffer[1];
      CRYP->DIN = buffer[2];
      CRYP->DIN = buffer[3];
   }

   //Once all header data have been supplied, wait until the BUSY bit is
   //cleared
   while((CRYP->SR & CRYP_SR_BUSY) != 0)
   {
   }

   //Set the CRYPEN bit to 0
   CRYP->CR &= ~CRYP_CR_CRYPEN;

   //Configure GCM_CCMPH bits to '10' to start GCM payload phase
   temp = CRYP->CR & ~CRYP_CR_GCM_CCMPH;
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_PAYLOAD;

   //Select the algorithm direction by using the ALGODIR bit
   temp = CRYP->CR & ~CRYP_CR_ALGODIR;
   CRYP->CR |= mode;

   //Set the CRYPEN bit to 1 to start accepting data
   CRYP->CR |= CRYP_CR_CRYPEN;

   //Process data
   for(n = length; n >= AES_BLOCK_SIZE; n -= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(input);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 12);

      //Wait for the output to be ready
      while((CRYP->SR & CRYP_SR_OFNE) == 0)
      {
      }

      //Read the output FIFO
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = CRYP->DOUT;
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

      //Specify the number of padding bytes in the last block
      temp = CRYP->CR & ~CRYP_CR_NPBLB;
      CRYP->CR = temp | ((AES_BLOCK_SIZE - n) << CRYP_CR_NPBLB_Pos);

      //Wait for the input FIFO to be ready to accept data
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = buffer[0];
      CRYP->DIN = buffer[1];
      CRYP->DIN = buffer[2];
      CRYP->DIN = buffer[3];

      //Wait for the output to be ready
      while((CRYP->SR & CRYP_SR_OFNE) == 0)
      {
      }

      //Read the output FIFO
      buffer[0] = CRYP->DOUT;
      buffer[1] = CRYP->DOUT;
      buffer[2] = CRYP->DOUT;
      buffer[3] = CRYP->DOUT;

      //Copy partial block
      osMemcpy(output, buffer, n);
   }

   //Once all payload data have been supplied, wait until the BUSY flag is
   //cleared
   while((CRYP->SR & CRYP_SR_BUSY) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '11' to start GCM final phase
   temp = CRYP->CR & ~CRYP_CR_GCM_CCMPH;
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_FINAL;

   //Write the input into the CRYP_DIN register 4 times. The input must
   //contain the number of bits in the header (64 bits) concatenated with
   //the number of bits in the payload (64 bits)
   m = aLen * 8;
   CRYP->DIN = htole32(m >> 32);
   CRYP->DIN = htole32(m);
   m = length * 8;
   CRYP->DIN = htole32(m >> 32);
   CRYP->DIN = htole32(m);

   //Wait until the OFNE flag is set to 1 in the CRYP_SR register
   while((CRYP->SR & CRYP_SR_OFNE) == 0)
   {
   }

   //Read the CRYP_DOUT register 4 times. The output corresponds to the
   //authentication tag
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t, temp);
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t + 4, temp);
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t + 8, temp);
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t + 12, temp);

   //Disable the cryptographic processor by clearing the CRYPEN bit
   CRYP->CR = 0;

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32n6xxCryptoMutex);
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
      authTag, CRYP_CR_ALGODIR);

   //The calculated tag is bitwise compared to the received tag
   for(mask = 0, i = 0; i < tLen; i++)
   {
      mask |= authTag[i] ^ t[i];
   }

   //The message is authenticated if and only if the tags match
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (CCM_SUPPORT == ENABLED)

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
   uint8_t buffer[16];

   //Acquire exclusive access to the CRYP module
   osAcquireMutex(&stm32n6xxCryptoMutex);

   //Configure the data type
   CRYP->CR = CRYP_CR_DATATYPE_8B;

   //Select the CCM chaining mode by programming ALGOMODE bits to '01001'
   temp = CRYP->CR & ~CRYP_CR_ALGOMODE;
   CRYP->CR = temp | CRYP_CR_ALGOMODE_AES_CCM;

   //Configure GCM_CCMPH bits to '00' to start the CCM init phase
   temp = CRYP->CR & ~CRYP_CR_GCM_CCMPH;
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_INIT;

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
   CRYP->IV0LR = LOAD32BE(buffer);
   CRYP->IV0RR = LOAD32BE(buffer + 4);
   CRYP->IV1LR = LOAD32BE(buffer + 8);
   CRYP->IV1RR = LOAD32BE(buffer + 12);

   //Set the CRYPEN bit to 1 in CRYP_CR to start accepting data
   CRYP->CR |= CRYP_CR_CRYPEN;

   //Write the B0 packet into CRYP_DIN register
   CRYP->DIN = LOAD32BE(b0);
   CRYP->DIN = LOAD32BE(b0 + 4);
   CRYP->DIN = LOAD32BE(b0 + 8);
   CRYP->DIN = LOAD32BE(b0 + 12);

   //Wait for the CRYPEN bit to be cleared to 0 by the cryptographic processor
   //before moving on to the next phase
   while((CRYP->CR & CRYP_CR_CRYPEN) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '01' to start CCM header phase
   temp = CRYP->CR & ~CRYP_CR_GCM_CCMPH;
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_HEADER;

   //Flush the input and output FIFOs
   CRYP->CR |= CRYP_CR_FFLUSH;
   //Set the CRYPEN bit to 1 to start accepting data
   CRYP->CR |= CRYP_CR_CRYPEN;

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
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 12);

      //Number of remaining data bytes
      aLen -= n;
      a += n;
   }

   //Process additional authenticated data
   while(aLen >= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(a);
      CRYP->DIN = __UNALIGNED_UINT32_READ(a + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(a + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(a + 12);

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
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 12);
   }

   //Once all header data have been supplied, wait until the BUSY bit is
   //cleared
   while((CRYP->SR & CRYP_SR_BUSY) != 0)
   {
   }

   //Set the CRYPEN bit to 0
   CRYP->CR &= ~CRYP_CR_CRYPEN;

   //Configure GCM_CCMPH bits to '10' to start CCM payload phase
   temp = CRYP->CR & ~CRYP_CR_GCM_CCMPH;
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_PAYLOAD;

   //Select the algorithm direction by using the ALGODIR bit
   temp = CRYP->CR & ~CRYP_CR_ALGODIR;
   CRYP->CR |= mode;

   //Set the CRYPEN bit to 1 to start accepting data
   CRYP->CR |= CRYP_CR_CRYPEN;

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //Wait for the input FIFO to be ready to accept data
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(input);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(input + 12);

      //Wait for the output to be ready
      while((CRYP->SR & CRYP_SR_OFNE) == 0)
      {
      }

      //Read the output FIFO
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output + 4, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(output + 8, temp);
      temp = CRYP->DOUT;
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

      //Specify the number of padding bytes in the last block
      temp = CRYP->CR & ~CRYP_CR_NPBLB;
      CRYP->CR = temp | ((AES_BLOCK_SIZE - length) << CRYP_CR_NPBLB_Pos);

      //Wait for the input FIFO to be ready to accept data
      while((CRYP->SR & CRYP_SR_IFNF) == 0)
      {
      }

      //Write the input FIFO
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 4);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 8);
      CRYP->DIN = __UNALIGNED_UINT32_READ(buffer + 12);

      //Wait for the output to be ready
      while((CRYP->SR & CRYP_SR_OFNE) == 0)
      {
      }

      //Read the output FIFO
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(buffer, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(buffer + 4, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(buffer + 8, temp);
      temp = CRYP->DOUT;
      __UNALIGNED_UINT32_WRITE(buffer + 12, temp);

      //Discard the bits that are not part of the payload when the last block
      //size is less than 16 bytes
      osMemcpy(output, buffer, length);
   }

   //Once all payload data have been supplied, wait until the BUSY flag is
   //cleared
   while((CRYP->SR & CRYP_SR_BUSY) != 0)
   {
   }

   //Configure GCM_CCMPH bits to '11' in CRYP_CR to indicate that the CCM final
   //phase is ongoing and set the ALGODIR bit to 0 in the same register
   temp = CRYP->CR & ~(CRYP_CR_GCM_CCMPH | CRYP_CR_ALGODIR);
   CRYP->CR = temp | CRYP_CR_GCM_CCMPH_FINAL;

   //Format CTR(0)
   osMemcpy(buffer, b0, 16 - qLen);
   osMemset(buffer + 16 - qLen, 0, qLen);

   //Set the leading octet
   buffer[0] = (uint8_t) (qLen - 1);

   //Load in CRYP_DIN the CTR(0) information
   CRYP->DIN = LOAD32BE(buffer);
   CRYP->DIN = LOAD32BE(buffer + 4);
   CRYP->DIN = LOAD32BE(buffer + 8);
   CRYP->DIN = LOAD32BE(buffer + 12);

   //Wait until the OFNE flag is set to 1 in the CRYP_SR register
   while((CRYP->SR & CRYP_SR_OFNE) == 0)
   {
   }

   //Read the CRYP_DOUT register 4 times. The output corresponds to the
   //authentication tag
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t, temp);
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t + 4, temp);
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t + 8, temp);
   temp = CRYP->DOUT;
   __UNALIGNED_UINT32_WRITE(t + 12, temp);

   //Disable the cryptographic processor by clearing the CRYPEN bit
   CRYP->CR = 0;

   //Release exclusive access to the CRYP module
   osReleaseMutex(&stm32n6xxCryptoMutex);
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

   //The CRYP module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Make sure the cipher context is valid
   if(context == NULL)
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

   //The CRYP module only supports AES cipher algorithm
   if(cipher != AES_CIPHER_ALGO)
      return ERROR_INVALID_PARAMETER;

   //Make sure the cipher context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format first block B(0)
   error = ccmFormatBlock0(length, n, nLen, aLen, tLen, b0);
   //Invalid parameters?
   if(error)
      return error;

   //Perform AES-CCM decryption
   ccmProcessData(context, b0, a, aLen, c, p, length, authTag, CRYP_CR_ALGODIR);

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
