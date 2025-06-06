/**
 * @file nuc472_crypto_cipher.c
 * @brief NUC472 cipher hardware accelerator
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
#include "nuc472_442.h"
#include "core/crypto.h"
#include "hardware/nuc472/nuc472_crypto.h"
#include "hardware/nuc472/nuc472_crypto_cipher.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (NUC472_CRYPTO_CIPHER_SUPPORT == ENABLED)


/**
 * @brief Encrypt/decrypt a 16-byte block using DES algorithm
 * @param[in] input Input block to be encrypted/decrypted
 * @param[out] output Resulting block
 **/

void desProcessDataBlock(const uint8_t *input, uint8_t *output)
{
   uint32_t temp;

   //Start TDES encryption/decryption
   CRPT->TDES_CTL |= CRPT_TDES_CTL_DMALAST_Msk | CRPT_TDES_CTL_START_Msk;

   //Poll INBUFFULL flag
   while((CRPT->TDES_STS & CRPT_TDES_STS_INBUFFULL_Msk) != 0)
   {
   }

   //Write input block CRYPTO_TDES_DATIN
   CRPT->TDES_DATIN = __UNALIGNED_UINT32_READ(input);
   CRPT->TDES_DATIN = __UNALIGNED_UINT32_READ(input + 4);

   //Poll OUTBUFEMPTY flag
   while((CRPT->TDES_STS & CRPT_TDES_STS_OUTBUFEMPTY_Msk) != 0)
   {
   }

   //Read output block from CRYPTO_TDES_DATOUT
   temp = CRPT->TDES_DATOUT;
   __UNALIGNED_UINT32_WRITE(output, temp);
   temp = CRPT->TDES_DATOUT;
   __UNALIGNED_UINT32_WRITE(output + 4, temp);

   //Save feedback information
   CRPT->TDES0_IVH = CRPT->TDES_FDBCKH;
   CRPT->TDES0_IVL = CRPT->TDES_FDBCKL;
}


#if (DES_SUPPORT == ENABLED)

/**
 * @brief Perform DES encryption or decryption
 * @param[in] context DES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] opmode Operation mode
 **/

void desProcessData(DesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t opmode)
{
   uint32_t temp;

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&nuc472CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Configure operation mode
   CRPT->TDES_CTL = CRPT_TDES_CTL_KEYPRT_Msk | CRPT_TDES_CTL_INSWAP_Msk |
      CRPT_TDES_CTL_OUTSWAP_Msk | CRPT_TDES_CTL_BLKSWAP_Msk | opmode;

   //Set encryption key
   CRPT->TDES0_KEY1H = context->ks[0];
   CRPT->TDES0_KEY1L = context->ks[1];

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      CRPT->TDES0_IVH = LOAD32BE(iv);
      CRPT->TDES0_IVL = LOAD32BE(iv + 4);
   }

   //Process data
   while(length >= DES_BLOCK_SIZE)
   {
      //The data is encrypted block by block
      desProcessDataBlock(input, output);

      //Next block
      input += DES_BLOCK_SIZE;
      output += DES_BLOCK_SIZE;
      length -= DES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint8_t buffer[DES_BLOCK_SIZE];

      //Copy input data
      osMemset(buffer, 0, DES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Encrypt the final block of data
      desProcessDataBlock(buffer, buffer);

      //Copy output data
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = CRPT->TDES_FDBCKH;
      STORE32BE(temp, iv);
      temp = CRPT->TDES_FDBCKL;
      STORE32BE(temp, iv + 4);
   }

   //Stop TDES engine
   CRPT->TDES_CTL |= CRPT_TDES_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&nuc472CryptoMutex);
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
      CRPT_TDES_CTL_OPMODE_ECB | CRPT_TDES_CTL_ENCRPT_Msk);
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
      CRPT_TDES_CTL_OPMODE_ECB);
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
 * @param[in] opmode Operation mode
 **/

void des3ProcessData(Des3Context *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t opmode)
{
   uint32_t temp;

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&nuc472CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Configure operation mode
   CRPT->TDES_CTL = CRPT_TDES_CTL_KEYPRT_Msk | CRPT_TDES_CTL_INSWAP_Msk |
      CRPT_TDES_CTL_OUTSWAP_Msk | CRPT_TDES_CTL_BLKSWAP_Msk |
      CRPT_TDES_CTL_3KEYS_Msk | CRPT_TDES_CTL_TMODE_Msk | opmode;

   //Set encryption key
   CRPT->TDES0_KEY1H = context->k1.ks[0];
   CRPT->TDES0_KEY1L = context->k1.ks[1];
   CRPT->TDES0_KEY2H = context->k2.ks[0];
   CRPT->TDES0_KEY2L = context->k2.ks[1];
   CRPT->TDES0_KEY3H = context->k3.ks[0];
   CRPT->TDES0_KEY3L = context->k3.ks[1];

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      CRPT->TDES0_IVH = LOAD32BE(iv);
      CRPT->TDES0_IVL = LOAD32BE(iv + 4);
   }

   //Process data
   while(length >= DES_BLOCK_SIZE)
   {
      //The data is encrypted block by block
      desProcessDataBlock(input, output);

      //Next block
      input += DES_BLOCK_SIZE;
      output += DES_BLOCK_SIZE;
      length -= DES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint8_t buffer[DES_BLOCK_SIZE];

      //Copy input data
      osMemset(buffer, 0, DES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Encrypt the final block of data
      desProcessDataBlock(buffer, buffer);

      //Copy output data
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = CRPT->TDES_FDBCKH;
      STORE32BE(temp, iv);
      temp = CRPT->TDES_FDBCKL;
      STORE32BE(temp, iv + 4);
   }

   //Stop TDES engine
   CRPT->TDES_CTL |= CRPT_TDES_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&nuc472CryptoMutex);
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
      CRPT_TDES_CTL_OPMODE_ECB | CRPT_TDES_CTL_ENCRPT_Msk);
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
      CRPT_TDES_CTL_OPMODE_ECB);
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

   //Read mode register
   temp = CRPT->AES_CTL & ~CRPT_AES_CTL_KEYSZ_Pos;

   //Check the length of the key
   if(context->nr == 10)
   {
      //10 rounds are required for 128-bit key
      CRPT->AES_CTL = temp | CRPT_AES_CTL_KEYSZ_128B;

      //Set the 128-bit encryption key
      CRPT->AES0_KEY0 = context->ek[0];
      CRPT->AES0_KEY1 = context->ek[1];
      CRPT->AES0_KEY2 = context->ek[2];
      CRPT->AES0_KEY3 = context->ek[3];
   }
   else if(context->nr == 12)
   {
      //12 rounds are required for 192-bit key
      CRPT->AES_CTL = temp | CRPT_AES_CTL_KEYSZ_192B;

      //Set the 192-bit encryption key
      CRPT->AES0_KEY0 = context->ek[0];
      CRPT->AES0_KEY1 = context->ek[1];
      CRPT->AES0_KEY2 = context->ek[2];
      CRPT->AES0_KEY3 = context->ek[3];
      CRPT->AES0_KEY4 = context->ek[4];
      CRPT->AES0_KEY5 = context->ek[5];
   }
   else
   {
      //14 rounds are required for 256-bit key
      CRPT->AES_CTL = temp | CRPT_AES_CTL_KEYSZ_256B;

      //Set the 256-bit encryption key
      CRPT->AES0_KEY0 = context->ek[0];
      CRPT->AES0_KEY1 = context->ek[1];
      CRPT->AES0_KEY2 = context->ek[2];
      CRPT->AES0_KEY3 = context->ek[3];
      CRPT->AES0_KEY4 = context->ek[4];
      CRPT->AES0_KEY5 = context->ek[5];
      CRPT->AES0_KEY6 = context->ek[6];
      CRPT->AES0_KEY7 = context->ek[7];
   }
}


/**
 * @brief Encrypt/decrypt a 16-byte block using AES algorithm
 * @param[in] input Input block to be encrypted/decrypted
 * @param[out] output Resulting block
 **/

void aesProcessDataBlock(const uint8_t *input, uint8_t *output)
{
   uint32_t temp;

   //Start AES encryption/decryption
   CRPT->AES_CTL |= CRPT_AES_CTL_DMALAST_Msk | CRPT_AES_CTL_START_Msk;

   //Poll INBUFFULL flag
   while((CRPT->AES_STS & CRPT_AES_STS_INBUFFULL_Msk) != 0)
   {
   }

   //Write input block CRYPTO_AES_DATIN
   CRPT->AES_DATIN = __UNALIGNED_UINT32_READ(input);
   CRPT->AES_DATIN = __UNALIGNED_UINT32_READ(input + 4);
   CRPT->AES_DATIN = __UNALIGNED_UINT32_READ(input + 8);
   CRPT->AES_DATIN = __UNALIGNED_UINT32_READ(input + 12);

   //Poll OUTBUFEMPTY flag
   while((CRPT->AES_STS & CRPT_AES_STS_OUTBUFEMPTY_Msk) != 0)
   {
   }

   //Read output block from CRYPTO_AES_DATOUT
   temp = CRPT->AES_DATOUT;
   __UNALIGNED_UINT32_WRITE(output, temp);
   temp = CRPT->AES_DATOUT;
   __UNALIGNED_UINT32_WRITE(output + 4, temp);
   temp = CRPT->AES_DATOUT;
   __UNALIGNED_UINT32_WRITE(output + 8, temp);
   temp = CRPT->AES_DATOUT;
   __UNALIGNED_UINT32_WRITE(output + 12, temp);

   //Save feedback information
   CRPT->AES0_IV0 = CRPT->AES_FDBCK0;
   CRPT->AES0_IV1 = CRPT->AES_FDBCK1;
   CRPT->AES0_IV2 = CRPT->AES_FDBCK2;
   CRPT->AES0_IV3 = CRPT->AES_FDBCK3;
}


/**
 * @brief Perform AES encryption or decryption
 * @param[in] context AES algorithm context
 * @param[in,out] iv Initialization vector
 * @param[in] input Data to be encrypted/decrypted
 * @param[out] output Data resulting from the encryption/decryption process
 * @param[in] length Total number of data bytes to be processed
 * @param[in] opmode Operation mode
 **/

void aesProcessData(AesContext *context, uint8_t *iv, const uint8_t *input,
   uint8_t *output, size_t length, uint32_t opmode)
{
   uint32_t temp;

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&nuc472CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Configure operation mode
   CRPT->AES_CTL = CRPT_AES_CTL_KEYPRT_Msk | CRPT_AES_CTL_INSWAP_Msk |
      CRPT_AES_CTL_OUTSWAP_Msk | opmode;

   //Set encryption key
   aesLoadKey(context);

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Set initialization vector
      CRPT->AES0_IV0 = LOAD32BE(iv);
      CRPT->AES0_IV1 = LOAD32BE(iv + 4);
      CRPT->AES0_IV2 = LOAD32BE(iv + 8);
      CRPT->AES0_IV3 = LOAD32BE(iv + 12);
   }

   //Process data
   while(length >= AES_BLOCK_SIZE)
   {
      //The data is encrypted block by block
      aesProcessDataBlock(input, output);

      //Next block
      input += AES_BLOCK_SIZE;
      output += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
   }

   //Process final block of data
   if(length > 0)
   {
      uint8_t buffer[AES_BLOCK_SIZE];

      //Copy input data
      osMemset(buffer, 0, AES_BLOCK_SIZE);
      osMemcpy(buffer, input, length);

      //Encrypt the final block of data
      aesProcessDataBlock(buffer, buffer);

      //Copy output data
      osMemcpy(output, buffer, length);
   }

   //Valid initialization vector?
   if(iv != NULL)
   {
      //Update the value of the initialization vector
      temp = CRPT->AES_FDBCK0;
      STORE32BE(temp, iv);
      temp = CRPT->AES_FDBCK1;
      STORE32BE(temp, iv + 4);
      temp = CRPT->AES_FDBCK2;
      STORE32BE(temp, iv + 8);
      temp = CRPT->AES_FDBCK3;
      STORE32BE(temp, iv + 12);
   }

   //Stop AES engine
   CRPT->AES_CTL |= CRPT_AES_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&nuc472CryptoMutex);
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
      //12 rounds are required for 256-bit key
      context->nr = 12;
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
      CRPT_AES_CTL_OPMODE_ECB | CRPT_AES_CTL_ENCRPT_Msk);
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
      CRPT_AES_CTL_OPMODE_ECB);
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
         desProcessData(context, NULL, p, c, length,
            CRPT_TDES_CTL_OPMODE_ECB | CRPT_TDES_CTL_ENCRPT_Msk);
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
         des3ProcessData(context, NULL, p, c, length,
            CRPT_TDES_CTL_OPMODE_ECB | CRPT_TDES_CTL_ENCRPT_Msk);
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
         aesProcessData(context, NULL, p, c, length,
            CRPT_AES_CTL_OPMODE_ECB | CRPT_AES_CTL_ENCRPT_Msk);
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
         desProcessData(context, NULL, c, p, length,
            CRPT_TDES_CTL_OPMODE_ECB);
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
         des3ProcessData(context, NULL, c, p, length,
            CRPT_TDES_CTL_OPMODE_ECB);
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
         aesProcessData(context, NULL, c, p, length,
            CRPT_AES_CTL_OPMODE_ECB);
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
         desProcessData(context, iv, p, c, length,
            CRPT_TDES_CTL_OPMODE_CBC | CRPT_TDES_CTL_ENCRPT_Msk);
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
         des3ProcessData(context, iv, p, c, length,
            CRPT_TDES_CTL_OPMODE_CBC | CRPT_TDES_CTL_ENCRPT_Msk);
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
         aesProcessData(context, iv, p, c, length,
            CRPT_AES_CTL_OPMODE_CBC | CRPT_AES_CTL_ENCRPT_Msk);
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
         desProcessData(context, iv, c, p, length,
            CRPT_TDES_CTL_OPMODE_CBC);
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
         des3ProcessData(context, iv, c, p, length,
            CRPT_TDES_CTL_OPMODE_CBC);
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
         aesProcessData(context, iv, c, p, length,
            CRPT_AES_CTL_OPMODE_CBC);
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

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            desProcessData(context, iv, p, c, length,
               CRPT_TDES_CTL_OPMODE_CFB | CRPT_TDES_CTL_ENCRPT_Msk);
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
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            des3ProcessData(context, iv, p, c, length,
               CRPT_TDES_CTL_OPMODE_CFB | CRPT_TDES_CTL_ENCRPT_Msk);
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
#endif
#if (AES_SUPPORT == ENABLED)
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
            aesProcessData(context, iv, p, c, length,
               CRPT_AES_CTL_OPMODE_CFB | CRPT_AES_CTL_ENCRPT_Msk);
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
#endif
   //Unknown cipher algorithm?
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

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            desProcessData(context, iv, c, p, length,
               CRPT_TDES_CTL_OPMODE_CFB);
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
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Decrypt payload data
            des3ProcessData(context, iv, c, p, length,
               CRPT_TDES_CTL_OPMODE_CFB);
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
#endif
#if (AES_SUPPORT == ENABLED)
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
            aesProcessData(context, iv, c, p, length,
               CRPT_AES_CTL_OPMODE_CFB);
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
#endif
   //Unknown cipher algorithm?
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
#if (OFB_SUPPORT == ENABLED)

/**
 * @brief OFB encryption
 * @param[in] cipher Cipher algorithm
 * @param[in] context Cipher algorithm context
 * @param[in] s Size of the plaintext and ciphertext segments
 * @param[in,out] iv Initialization vector
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @return Error code
 **/

error_t ofbEncrypt(const CipherAlgo *cipher, void *context, uint_t s,
   uint8_t *iv, const uint8_t *p, uint8_t *c, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (DES_SUPPORT == ENABLED)
   //DES cipher algorithm?
   if(cipher == DES_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            desProcessData(context, iv, p, c, length,
               CRPT_TDES_CTL_OPMODE_OFB | CRPT_TDES_CTL_ENCRPT_Msk);
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
#endif
#if (DES3_SUPPORT == ENABLED)
   //Triple DES cipher algorithm?
   if(cipher == DES3_CIPHER_ALGO)
   {
      //Check the value of the parameter
      if(s == (DES3_BLOCK_SIZE * 8))
      {
         //Check the length of the payload
         if(length > 0)
         {
            //Encrypt payload data
            des3ProcessData(context, iv, p, c, length,
               CRPT_TDES_CTL_OPMODE_OFB | CRPT_TDES_CTL_ENCRPT_Msk);
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
#endif
#if (AES_SUPPORT == ENABLED)
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
            aesProcessData(context, iv, p, c, length,
               CRPT_AES_CTL_OPMODE_OFB | CRPT_AES_CTL_ENCRPT_Msk);
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
#endif
   //Unknown cipher algorithm?
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

            //Compute I(j+1) = LSB(I(j)) | O(j)
            osMemmove(iv, iv + s, cipher->blockSize - s);
            osMemcpy(iv + cipher->blockSize - s, o, s);

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

#if (DES_SUPPORT == ENABLED)
      //DES cipher algorithm?
      if(cipher == DES_CIPHER_ALGO)
      {
         size_t k;
         size_t n;
         uint8_t iv[DES_BLOCK_SIZE];

         //Process plaintext
         while(length > 0)
         {
            //Limit the number of blocks to process at a time
            k = 256 - t[DES_BLOCK_SIZE - 1];
            n = MIN(length, k * DES_BLOCK_SIZE);
            k = (n + DES_BLOCK_SIZE - 1) / DES_BLOCK_SIZE;

            //Copy initial counter value
            osMemcpy(iv, t, DES_BLOCK_SIZE);

            //Encrypt payload data
            desProcessData(context, iv, p, c, n,
               CRPT_TDES_CTL_OPMODE_CTR | CRPT_TDES_CTL_ENCRPT_Msk);

            //Standard incrementing function
            ctrIncBlock(t, k, DES_BLOCK_SIZE, m);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
#endif
#if (DES3_SUPPORT == ENABLED)
      //Triple DES cipher algorithm?
      if(cipher == DES3_CIPHER_ALGO)
      {
         size_t k;
         size_t n;
         uint8_t iv[DES3_BLOCK_SIZE];

         //Process plaintext
         while(length > 0)
         {
            //Limit the number of blocks to process at a time
            k = 256 - t[DES3_BLOCK_SIZE - 1];
            n = MIN(length, k * DES3_BLOCK_SIZE);
            k = (n + DES3_BLOCK_SIZE - 1) / DES3_BLOCK_SIZE;

            //Copy initial counter value
            osMemcpy(iv, t, DES3_BLOCK_SIZE);

            //Encrypt payload data
            des3ProcessData(context, iv, p, c, n,
               CRPT_TDES_CTL_OPMODE_CTR | CRPT_TDES_CTL_ENCRPT_Msk);

            //Standard incrementing function
            ctrIncBlock(t, k, DES3_BLOCK_SIZE, m);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
#endif
#if (AES_SUPPORT == ENABLED)
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
            aesProcessData(context, iv, p, c, n,
               CRPT_AES_CTL_OPMODE_CTR | CRPT_AES_CTL_ENCRPT_Msk);

            //Standard incrementing function
            ctrIncBlock(t, k, AES_BLOCK_SIZE, m);

            //Next block
            p += n;
            c += n;
            length -= n;
         }
      }
      else
#endif
      //Unknown cipher algorithm?
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
 * @brief Increment counter block
 * @param[in,out] ctr Pointer to the counter block
 * @param[in] inc Value of the increment
 **/

void gcmIncBlock(uint8_t *ctr, uint32_t inc)
{
   size_t i;
   uint32_t temp;

   //The function increments the right-most bytes of the block. The remaining
   //left-most bytes remain unchanged
   for(temp = inc, i = 0; i <= 3; i++)
   {
      //Increment the current byte and propagate the carry
      temp += ctr[15 - i];
      ctr[15 - i] = temp & 0xFF;
      temp >>= 8;
   }
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

error_t gcmEncrypt(GcmContext *context, const uint8_t *iv, size_t ivLen,
   const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c, size_t length,
   uint8_t *t, size_t tLen)
{
   size_t i;
   size_t n;
   uint8_t b[16];
   uint8_t j[16];
   uint8_t s[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Check whether the length of the IV is 96 bits
   if(ivLen == 12)
   {
      //When the length of the IV is 96 bits, the padding string is appended
      //to the IV to form the pre-counter block
      osMemcpy(j, iv, 12);
      STORE32BE(1, j + 12);
   }
   else
   {
      //Initialize GHASH calculation
      osMemset(j, 0, 16);

      //Process the initialization vector
      for(i = 0; i < ivLen; i += n)
      {
         //The IV is processed in a block-by-block fashion
         n = MIN(ivLen - i, 16);

         //Apply GHASH function
         gcmXorBlock(j, j, iv + i, n);
         gcmMul(context, j);
      }

      //The string is appended with 64 additional 0 bits, followed by the
      //64-bit representation of the length of the IV
      osMemset(b, 0, 8);
      STORE64BE(ivLen * 8, b + 8);

      //The GHASH function is applied to the resulting string to form the
      //pre-counter block
      gcmXorBlock(j, j, b, 16);
      gcmMul(context, j);
   }

   //Compute MSB(CIPH(J(0)))
   context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
   osMemcpy(t, b, tLen);

   //Initialize GHASH calculation
   osMemset(s, 0, 16);

   //Process AAD
   for(i = 0; i < aLen; i += n)
   {
      //Additional data are processed in a block-by-block fashion
      n = MIN(aLen - i, 16);

      //Apply GHASH function
      gcmXorBlock(s, s, a + i, n);
      gcmMul(context, s);
   }

   //Increment counter
   gcmIncCounter(j);

   //AES cipher algorithm?
   if(context->cipherAlgo == AES_CIPHER_ALGO)
   {
      //Encrypt plaintext
      for(i = 0; i < length; i += n)
      {
         size_t k;
         uint8_t iv[AES_BLOCK_SIZE];

         //Limit the number of blocks to process at a time
         k = 256 - j[AES_BLOCK_SIZE - 1];
         n = MIN(length, k * AES_BLOCK_SIZE);
         k = (n + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

         //Copy initial counter value
         osMemcpy(iv, j, AES_BLOCK_SIZE);

         //Encrypt payload data
         aesProcessData(context->cipherContext, iv, p + i, c + i, n,
            CRPT_AES_CTL_OPMODE_CTR | CRPT_AES_CTL_ENCRPT_Msk);

         //Increment the right-most 32 bits of the block
         gcmIncBlock(j, k);
      }
   }
   else
   {
      //Encrypt plaintext
      for(i = 0; i < length; i += n)
      {
         //The encryption operates in a block-by-block fashion
         n = MIN(length - i, 16);

         //Encrypt current block
         context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
         gcmXorBlock(c + i, p + i, b, n);

         //Increment counter
         gcmIncCounter(j);
      }
   }

   //Process ciphertext
   for(i = 0; i < length; i += n)
   {
      //The encryption operates in a block-by-block fashion
      n = MIN(length - i, 16);

      //Apply GHASH function
      gcmXorBlock(s, s, c + i, n);
      gcmMul(context, s);
   }

   //Append the 64-bit representation of the length of the AAD and the
   //ciphertext
   STORE64BE(aLen * 8, b);
   STORE64BE(length * 8, b + 8);

   //The GHASH function is applied to the result to produce a single output
   //block S
   gcmXorBlock(s, s, b, 16);
   gcmMul(context, s);

   //Let T = MSB(GCTR(J(0), S)
   gcmXorBlock(t, t, s, tLen);

   //Successful encryption
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

error_t gcmDecrypt(GcmContext *context, const uint8_t *iv, size_t ivLen,
   const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p, size_t length,
   const uint8_t *t, size_t tLen)
{
   uint8_t mask;
   size_t i;
   size_t n;
   uint8_t b[16];
   uint8_t j[16];
   uint8_t r[16];
   uint8_t s[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_LENGTH;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
      return ERROR_INVALID_LENGTH;

   //Check whether the length of the IV is 96 bits
   if(ivLen == 12)
   {
      //When the length of the IV is 96 bits, the padding string is appended
      //to the IV to form the pre-counter block
      osMemcpy(j, iv, 12);
      STORE32BE(1, j + 12);
   }
   else
   {
      //Initialize GHASH calculation
      osMemset(j, 0, 16);

      //Process the initialization vector
      for(i = 0; i < ivLen; i += n)
      {
         //The IV is processed in a block-by-block fashion
         n = MIN(ivLen - i, 16);

         //Apply GHASH function
         gcmXorBlock(j, j, iv + i, n);
         gcmMul(context, j);
      }

      //The string is appended with 64 additional 0 bits, followed by the
      //64-bit representation of the length of the IV
      osMemset(b, 0, 8);
      STORE64BE(ivLen * 8, b + 8);

      //The GHASH function is applied to the resulting string to form the
      //pre-counter block
      gcmXorBlock(j, j, b, 16);
      gcmMul(context, j);
   }

   //Compute MSB(CIPH(J(0)))
   context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
   osMemcpy(r, b, tLen);

   //Initialize GHASH calculation
   osMemset(s, 0, 16);

   //Process AAD
   for(i = 0; i < aLen; i += n)
   {
      //Additional data are processed in a block-by-block fashion
      n = MIN(aLen - i, 16);

      //Apply GHASH function
      gcmXorBlock(s, s, a + i, n);
      gcmMul(context, s);
   }

   //Process ciphertext
   for(i = 0; i < length; i += n)
   {
      //The decryption operates in a block-by-block fashion
      n = MIN(length - i, 16);

      //Apply GHASH function
      gcmXorBlock(s, s, c + i, n);
      gcmMul(context, s);
   }

   //Increment counter
   gcmIncCounter(j);

   //AES cipher algorithm?
   if(context->cipherAlgo == AES_CIPHER_ALGO)
   {
      //Decrypt ciphertext
      for(i = 0; i < length; i += n)
      {
         size_t k;
         uint8_t iv[AES_BLOCK_SIZE];

         //Limit the number of blocks to process at a time
         k = 256 - j[AES_BLOCK_SIZE - 1];
         n = MIN(length, k * AES_BLOCK_SIZE);
         k = (n + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

         //Copy initial counter value
         osMemcpy(iv, j, AES_BLOCK_SIZE);

         //Encrypt payload data
         aesProcessData(context->cipherContext, iv, c + i, p + i, n,
            CRPT_AES_CTL_OPMODE_CTR | CRPT_AES_CTL_ENCRPT_Msk);

         //Increment the right-most 32 bits of the block
         gcmIncBlock(j, k);
      }
   }
   else
   {
      //Decrypt ciphertext
      for(i = 0; i < length; i += n)
      {
         //The decryption operates in a block-by-block fashion
         n = MIN(length - i, 16);

         //Decrypt current block
         context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
         gcmXorBlock(p + i, c + i, b, n);

         //Increment counter
         gcmIncCounter(j);
      }
   }

   //Append the 64-bit representation of the length of the AAD and the
   //ciphertext
   STORE64BE(aLen * 8, b);
   STORE64BE(length * 8, b + 8);

   //The GHASH function is applied to the result to produce a single output
   //block S
   gcmXorBlock(s, s, b, 16);
   gcmMul(context, s);

   //Let R = MSB(GCTR(J(0), S))
   gcmXorBlock(r, r, s, tLen);

   //The calculated tag is bitwise compared to the received tag. The message
   //is authenticated if and only if the tags match
   for(mask = 0, n = 0; n < tLen; n++)
   {
      mask |= r[n] ^ t[n];
   }

   //Return status code
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif
