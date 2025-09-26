/**
 * @file ctr_drbg.c
 * @brief CTR_DRBG pseudorandom number generator
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
#include "core/crypto.h"
#include "rng/ctr_drbg.h"
#include "debug.h"

//Check crypto library configuration
#if (CTR_DRBG_SUPPORT == ENABLED)

//Padding string
static const uint8_t padding[MAX_CIPHER_BLOCK_SIZE] = {0};

//Common interface for PRNG algorithms
const PrngAlgo ctrDrbgPrngAlgo =
{
   "CTR_DRBG",
   sizeof(CtrDrbgContext),
   (PrngAlgoInit) NULL,
   (PrngAlgoSeed) ctrDrbgSeed,
   (PrngAlgoReseed) ctrDrbgReseed,
   (PrngAlgoGenerate) ctrDrbgGenerate,
   (PrngAlgoDeinit) ctrDrbgDeinit
};


/**
 * @brief Initialize PRNG context
 * @param[in] context Pointer to the CTR_DRBG context to initialize
 * @param[in] cipherAlgo Approved block cipher algorithm
 * @param[in] keyLen Key length, in bits
 * @param[in] df Use key derivation function
 * @return Error code
 **/

error_t ctrDrbgInit(CtrDrbgContext *context, const CipherAlgo *cipherAlgo,
   size_t keyLen, bool_t df)
{
   //Check parameters
   if(context == NULL || cipherAlgo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the internal state
   osMemset(context, 0, sizeof(CtrDrbgContext));

   //Create a mutex to prevent simultaneous access to the PRNG state
   if(!osCreateMutex(&context->mutex))
   {
      //Failed to create mutex
      return ERROR_OUT_OF_RESOURCES;
   }

#if (DES3_SUPPORT == ENABLED)
   //TDEA cipher algorithm?
   if(cipherAlgo == DES3_CIPHER_ALGO)
   {
      //TDEA uses 168-bit keys
      if(keyLen != 168)
         return ERROR_INVALID_KEY_LENGTH;

      //TDEA provides 112 bits of security strength
      context->securityStrength = 14;
   }
   else
#endif
#if (AES_SUPPORT == ENABLED)
   //AES cipher algorithm?
   if(cipherAlgo == AES_CIPHER_ALGO)
   {
      //TDEA uses 128, 192 or 256-bit keys
      if(keyLen != 128 && keyLen != 192 && keyLen != 256)
         return ERROR_INVALID_KEY_LENGTH;

      //AES provides 128, 192 or 256 bits of security strength
      context->securityStrength = keyLen / 8;
   }
   else
#endif
   //Unknown cipher algorithm?
   {
      //CTR_DRBG must use an approved block cipher algorithm
      return ERROR_UNSUPPORTED_CIPHER_ALGO;
   }

   //Save parameters
   context->cipherAlgo = cipherAlgo;
   context->keyLen = keyLen / 8;
   context->ctrLen = cipherAlgo->blockSize;
   context->df = df;

   //Determine the seed length
   context->seedLen = context->keyLen + cipherAlgo->blockSize;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Seed the PRNG state
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] seed String of bits obtained from the randomness source
 * @param[in] length Length of the string, in bytes
 * @return Error code
 **/

error_t ctrDrbgSeed(CtrDrbgContext *context, const uint8_t *seed,
   size_t length)
{
   //Seeding process
   return ctrDrbgSeedEx(context, seed, length, NULL, 0, NULL, 0);
}


/**
 * @brief Seed the PRNG state (with nonce and personalization string)
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] entropyInput String of bits obtained from the randomness source
 * @param[in] entropyInputLen Length of the string, in bytes
 * @param[in] nonce Nonce
 * @param[in] nonceLen Length of the nonce, in bytes
 * @param[in] personalizationString Personalization string received from the
 *   consuming application
 * @param[in] personalizationStringLen Length of the personalization string,
 *   in bytes
 * @return Error code
 **/

error_t ctrDrbgSeedEx(CtrDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *nonce, size_t nonceLen,
   const uint8_t *personalizationString, size_t personalizationStringLen)
{
   error_t error;
   size_t i;
   uint8_t seedMaterial[CTR_DRBG_MAX_SEED_LEN];

   //Check parameters
   if(context == NULL || entropyInput == NULL)
      return ERROR_INVALID_PARAMETER;

   //The nonce parameter is optional
   if(nonce == NULL && nonceLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The personalization_string parameter is optional
   if(personalizationString == NULL && personalizationStringLen != 0)
      return ERROR_INVALID_PARAMETER;

   //CTR_DRBG uses an approved block cipher algorithm
   if(context->cipherAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //Check is derivation function is used
   if(context->df)
   {
      //The entropy input shall have entropy that is equal to or greater than
      //the security strength of the instantiation
      if(entropyInputLen < context->securityStrength)
         return ERROR_INVALID_PARAMETER;

      //When instantiation is performed using this method, a nonce is required.
      //The length of the nonce shall be at least half the maximum security
      //strength supported
      if(nonceLen < (context->securityStrength / 2))
         return ERROR_INVALID_PARAMETER;
   }
   else
   {
      //The length of the entropy_input must be exactly seedlen
      if(entropyInputLen != context->seedLen)
         return ERROR_INVALID_PARAMETER;

      //The maximum length of the personalization_string is seedlen
      if(personalizationStringLen > context->seedLen)
         return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = NO_ERROR;

   //Check is derivation function is used
   if(context->df)
   {
      DataChunk input[3];

      //Let seed_material = entropy_input || nonce || personalization_string
      input[0].buffer = entropyInput;
      input[0].length = entropyInputLen;
      input[1].buffer = nonce;
      input[1].length = nonceLen;
      input[2].buffer = personalizationString;
      input[2].length = personalizationStringLen;

      //Compute seed_material = df(seed_material, seedlen)
      error = blockCipherDf(context, input, arraysize(input), seedMaterial,
         context->seedLen);
   }
   else
   {
      //Copy entropy input
      osMemcpy(seedMaterial, entropyInput, context->seedLen);

      //Compute seed_material = entropy_input + personalization_string
      for(i = 0; i < personalizationStringLen; i++)
      {
         seedMaterial[i] ^= personalizationString[i];
      }
   }

   //Check status code
   if(!error)
   {
      //Let Key be keylen bits of zeros
      osMemset(context->k, 0, context->keyLen);
      //Let V be blocklen bits of zeros
      osMemset(context->v, 0, context->cipherAlgo->blockSize);

      //Compute (Key, V) = CTR_DRBG_Update(seed_material, Key, V).
      error = ctrDrbgUpdate(context, seedMaterial, context->seedLen);
   }

   //Check status code
   if(!error)
   {
      //Reset reseed_counter
      context->reseedCounter = 1;
   }

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Reseed the PRNG state
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] seed String of bits obtained from the randomness source
 * @param[in] length Length of the string, in bytes
 * @return Error code
 **/

error_t ctrDrbgReseed(CtrDrbgContext *context, const uint8_t *seed,
   size_t length)
{
   //Reseeding process
   return ctrDrbgReseedEx(context, seed, length, NULL, 0);
}


/**
 * @brief Reseed the PRNG state (with additional input)
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] entropyInput String of bits obtained from the randomness source
 * @param[in] entropyInputLen Length of the string, in bytes
 * @param[in] additionalInput Additional input string received from the
 *   consuming application
 * @param[in] additionalInputLen Length of the additional input string, in bytes
 * @return Error code
 **/

error_t ctrDrbgReseedEx(CtrDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *additionalInput,
   size_t additionalInputLen)
{
   error_t error;
   size_t i;
   uint8_t seedMaterial[CTR_DRBG_MAX_SEED_LEN];

   //Check parameters
   if(context == NULL || entropyInput == NULL)
      return ERROR_INVALID_PARAMETER;

   //The additional_input parameter is optional
   if(additionalInput == NULL && additionalInputLen != 0)
      return ERROR_INVALID_PARAMETER;

   //CTR_DRBG uses an approved block cipher algorithm
   if(context->cipherAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //Check whether the DRBG has been properly instantiated
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //Check is derivation function is used
   if(context->df)
   {
      //The entropy input shall have entropy that is equal to or greater than
      //the security strength of the instantiation
      if(entropyInputLen < context->securityStrength)
         return ERROR_INVALID_PARAMETER;
   }
   else
   {
      //The length of the entropy_input must be exactly seedlen
      if(entropyInputLen != context->seedLen)
         return ERROR_INVALID_PARAMETER;

      //The maximum length of the additional_input is seedlen
      if(additionalInputLen > context->seedLen)
         return ERROR_INVALID_PARAMETER;
   }

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Check is derivation function is used
   if(context->df)
   {
      DataChunk input[2];

      //Let seed_material = entropy_input || additional_input
      input[0].buffer = entropyInput;
      input[0].length = entropyInputLen;
      input[1].buffer = additionalInput;
      input[1].length = additionalInputLen;

      //Compute seed_material = df(seed_material, seedlen)
      error = blockCipherDf(context, input, arraysize(input), seedMaterial,
         context->seedLen);
   }
   else
   {
      //Copy entropy input
      osMemcpy(seedMaterial, entropyInput, context->seedLen);

      //Compute seed_material = entropy_input + additional_input
      for(i = 0; i < additionalInputLen; i++)
      {
         seedMaterial[i] ^= additionalInput[i];
      }
   }

   //Check status code
   if(!error)
   {
      //Compute (Key, V) = CTR_DRBG_Update(seed_material, Key, V).
      error = ctrDrbgUpdate(context, seedMaterial, context->seedLen);
   }

   //Check status code
   if(!error)
   {
      //Reset reseed_counter
      context->reseedCounter = 1;
   }

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Generate pseudorandom data
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] length Requested number of bytes
 * @return Error code
 **/

error_t ctrDrbgGenerate(CtrDrbgContext *context, uint8_t *output,
   size_t length)
{
   //Generation process
   return ctrDrbgGenerateEx(context, NULL, 0, output, length);
}


/**
 * @brief Generate pseudorandom data (with additional input)
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] additionalInput Additional input string received from the
 *   consuming application
 * @param[in] additionalInputLen Length of the additional input string, in bytes
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] outputLen Requested number of bytes
 * @return Error code
 **/

error_t ctrDrbgGenerateEx(CtrDrbgContext *context,
   const uint8_t *additionalInput, size_t additionalInputLen, uint8_t *output,
   size_t outputLen)
{
   error_t error;
   size_t n;
   uint8_t temp[CTR_DRBG_MAX_SEED_LEN];
   uint8_t block[MAX_CIPHER_BLOCK_SIZE];
   const CipherAlgo *cipherAlgo;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The additional_input parameter is optional
   if(additionalInput == NULL && additionalInputLen != 0)
      return ERROR_INVALID_PARAMETER;

   //CTR_DRBG uses an approved block cipher algorithm
   if(context->cipherAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //A DRBG shall be instantiated prior to the generation of pseudorandom bits
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //If reseed_counter > reseed_interval, then return an indication that a
   //reseed is required
   if(context->reseedCounter > CTR_DRBG_MAX_RESEED_INTERVAL)
      return ERROR_RESEED_REQUIRED;

   //Derivation function not used?
   if(!context->df)
   {
      //The maximum length of the additional_input is seedlen
      if(additionalInputLen > context->seedLen)
         return ERROR_INVALID_PARAMETER;
   }

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //The length of the additional input string may be zero
   if(additionalInputLen > 0)
   {
      //Check is derivation function is used
      if(context->df)
      {
         DataChunk input[1];

         //Let seed_material = entropy_input || additional_input
         input[0].buffer = additionalInput;
         input[0].length = additionalInputLen;

         //Compute additional_input = Block_Cipher_df(additional_input, seedlen)
         error = blockCipherDf(context, input, arraysize(input), temp,
            context->seedLen);
      }
      else
      {
         //If the length of the additional input is less than seedlen, then pad
         //with zero bits
         osMemset(temp, 0, context->seedLen);
         osMemcpy(temp, additionalInput, additionalInputLen);
      }

      //Check status code
      if(!error)
      {
         //Compute (Key, V) = CTR_DRBG_Update(additional_input, Key, V)
         error = ctrDrbgUpdate(context, temp, context->seedLen);
      }
   }
   else
   {
      //Let additional_input be seedlen bits of zeros
      osMemset(temp, 0, context->seedLen);
   }

   //Check status code
   if(!error)
   {
      //Load encryption key
      error = ctrDrbgLoadKey(context, context->k);

      //Check status code
      if(!error)
      {
         //The block cipher operation uses the selected block cipher algorithm
         cipherAlgo = context->cipherAlgo;

         //Generate the requested number of bytes
         while(outputLen > 0)
         {
            //Number of bytes to generate at a time
            n = MIN(outputLen, cipherAlgo->blockSize);

            //Increment counter block
            ctrDrbgIncBlock(context->v, cipherAlgo->blockSize, context->ctrLen);

            //Compute output_block = Block_Encrypt(Key, V)
            cipherAlgo->encryptBlock(&context->cipherContext, context->v,
               block);

            //Copy data to the output buffer
            osMemcpy(output, block, n);

            //Next output block
            output += n;
            outputLen -= n;
         }

         //Release cipher context
         cipherAlgo->deinit(&context->cipherContext);
      }
   }

   //Check status code
   if(!error)
   {
      //Compute (Key, V) = CTR_DRBG_Update(additional_input, Key, V)
      error = ctrDrbgUpdate(context, temp, context->seedLen);
   }

   //Check status code
   if(!error)
   {
      //Increment reseed_counter
      context->reseedCounter++;
   }

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Release PRNG context
 * @param[in] context Pointer to the CTR_DRBG context
 **/

void ctrDrbgDeinit(CtrDrbgContext *context)
{
   //Valid CTR_DRBG context?
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteMutex(&context->mutex);

      //Erase the contents of the internal state
      osMemset(context, 0, sizeof(CtrDrbgContext));
   }
}


/**
 * @brief Block cipher derivation function
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] input The string to be operated on
 * @param[in] inputLen Number of data chunks representing the input
 * @param[out] output Buffer where to store the output value
 * @param[out] outputLen The number of bytes to be returned
 * @return Error code
 **/

error_t blockCipherDf(CtrDrbgContext *context, const DataChunk *input,
   uint_t inputLen, uint8_t *output, size_t outputLen)
{
   error_t error;
   uint32_t i;
   size_t j;
   size_t m;
   size_t totalInputLen;
   size_t paddingLen;
   uint8_t separator;
   uint8_t l[4];
   uint8_t n[4];
   uint8_t k[CTR_DRBG_MAX_KEY_LEN];
   uint8_t x[MAX_CIPHER_BLOCK_SIZE];
   uint8_t iv[MAX_CIPHER_BLOCK_SIZE];
   uint8_t block[MAX_CIPHER_BLOCK_SIZE];
   uint8_t temp[CTR_DRBG_MAX_SEED_LEN];
   DataChunk s[8];
   const CipherAlgo *cipherAlgo;

   //The maximum length (max_number_of_bits) is 512 bits for the currently
   //approved block cipher algorithms
   if(outputLen > 64)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if((inputLen + 5) > arraysize(s))
      return ERROR_INVALID_PARAMETER;

   //The block cipher operation uses the selected block cipher algorithm
   cipherAlgo = context->cipherAlgo;

   //Determine the length of the input string
   for(totalInputLen = 0, i = 0; i < inputLen; i++)
   {
      totalInputLen += input[i].length;
   }

   //L is the bitstring representation of the integer resulting from
   //len(input_string)/8. L shall be represented as a 32-bit integer
   STORE32BE(totalInputLen, l);

   //N is the bitstring representation of the integer resulting from
   //number_of_bits_to_return/8. N shall be represented as a 32-bit integer
   STORE32BE(outputLen, n);

   //Padding delimiter character
   separator = 0x80;

   //Prepare initialization vector
   osMemset(iv, 0, cipherAlgo->blockSize);

   //Let S = L || N || input_string || 0x80
   s[0].buffer = iv;
   s[0].length = cipherAlgo->blockSize;
   s[1].buffer = l;
   s[1].length = sizeof(l);
   s[2].buffer = n;
   s[2].length = sizeof(n);

   for(i = 0; i < inputLen; i++)
   {
      s[3 + i].buffer = input[i].buffer;
      s[3 + i].length = input[i].length;
   }

   s[3 + i].buffer = &separator;
   s[3 + i].length = sizeof(separator);

   //Get the actual amount of bytes in the last block
   paddingLen = (totalInputLen + 9) % cipherAlgo->blockSize;

   //Determine the length of the padding string
   if(paddingLen > 0)
   {
      paddingLen = cipherAlgo->blockSize - paddingLen;
   }

   //Pad S with zeros, if necessary
   s[4 + i].buffer = padding;
   s[4 + i].length = paddingLen;

   //Set K = leftmost(0x00010203...1D1E1F, keylen)
   for(i = 0; i < context->keyLen; i++)
   {
      k[i] = (uint8_t) i;
   }

   //Initialize block counter
   i = 0;

   //Generate keylen + outlen bytes
   for(j = 0; j < context->seedLen; j += m)
   {
      //Number of bytes to generate at a time
      m = MIN(context->seedLen - j, cipherAlgo->blockSize);

      //The 32-bit integer representation of i is padded with zeros to
      //outlen bits
      STORE32BE(i, iv);

      //Compute BCC(K, (IV || S)
      error = ctrDrbgBcc(context, k, s, inputLen + 5, block);
      //Any error to report?
      if(error)
         return error;

      //Copy data to the output buffer
      osMemcpy(temp + j, block, m);

      //Increment block counter
      i++;
   }

   //Set K = leftmost(temp, keylen)
   osMemcpy(k, temp, context->keyLen);
   //Set X = select(temp, keylen+1, keylen+outlen)
   osMemcpy(x, temp + context->keyLen, cipherAlgo->blockSize);

   //Load encryption key
   error = ctrDrbgLoadKey(context, k);
   //Any error to report?
   if(error)
      return error;

   //Generate the requested number of bytes
   while(outputLen > 0)
   {
      //Number of bytes to generate at a time
      m = MIN(outputLen, cipherAlgo->blockSize);

      //Compute X = Block_Encrypt(K, X)
      cipherAlgo->encryptBlock(&context->cipherContext, x, x);

      //Set temp = temp || X
      osMemcpy(output, x, m);

      //Next output block
      output += m;
      outputLen -= m;
   }

   //Release cipher context
   cipherAlgo->deinit(&context->cipherContext);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief BCC function
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] key The key to be used for the block cipher operation
 * @param[in] data The data to be operated on
 * @param[in] dataLen Number of data chunks representing the data
 * @param[out] output The result to be returned from the BCC operation
 * @return Error code
 **/

error_t ctrDrbgBcc(CtrDrbgContext *context, const uint8_t *key,
   const DataChunk *data, uint_t dataLen, uint8_t *output)
{
   error_t error;
   uint_t i;
   size_t j;
   size_t n;
   size_t blockLen;
   uint8_t block[MAX_CIPHER_BLOCK_SIZE];
   uint8_t chainingValue[MAX_CIPHER_BLOCK_SIZE];
   const CipherAlgo *cipherAlgo;

   //The block cipher operation uses the selected block cipher algorithm
   cipherAlgo = context->cipherAlgo;

   //Determine the length of the input data
   for(n = 0, i = 0; i < dataLen; i++)
   {
      n += data[i].length;
   }

   //The length of data must be a multiple of outlen
   if((n % cipherAlgo->blockSize) != 0)
      return ERROR_INVALID_LENGTH;

   //Load encryption key
   error = ctrDrbgLoadKey(context, key);
   //Any error to report?
   if(error)
      return error;

   //Set the first chaining value to outlen zeros
   osMemset(chainingValue, 0, cipherAlgo->blockSize);

   //Initialize block length
   blockLen = 0;

   //Process input data
   for(i = 0; i < dataLen; i++)
   {
      for(j = 0; j < data[i].length; j += n)
      {
         //Number of bytes to process at a time
         n = MIN(data[i].length - j, cipherAlgo->blockSize - blockLen);

         //Copy the data to the buffer
         osMemcpy(block + blockLen, (uint8_t *) data[i].buffer + j, n);
         //Adjust the length of the buffer
         blockLen += n;

         //Split data into n blocks of outlen bits each
         if(blockLen == cipherAlgo->blockSize)
         {
            //Compute input_block = chaining_value + block(i)
            ctrDrbgXorBlock(block, chainingValue, block, cipherAlgo->blockSize);

            //Compute chaining_value = Block_Encrypt(Key, input_block)
            cipherAlgo->encryptBlock(&context->cipherContext, block,
               chainingValue);

            //Empty the buffer
            blockLen = 0;
         }
      }
   }

   //Set output_block = chaining_value
   osMemcpy(output, chainingValue, cipherAlgo->blockSize);

   //Release cipher context
   cipherAlgo->deinit(&context->cipherContext);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Update internal state
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] providedData The data to be used
 * @param[in] providedDataLen Length of the data, in bytes
 * @return Error code
 **/

error_t ctrDrbgUpdate(CtrDrbgContext *context, const uint8_t *providedData,
   size_t providedDataLen)
{
   error_t error;
   size_t i;
   size_t n;
   uint8_t temp[CTR_DRBG_MAX_SEED_LEN];
   uint8_t block[MAX_CIPHER_BLOCK_SIZE];
   const CipherAlgo *cipherAlgo;

   //The provided_data must be exactly seedlen bits in length
   if(providedDataLen != context->seedLen)
      return ERROR_INVALID_PARAMETER;

   //Load encryption key
   error = ctrDrbgLoadKey(context, context->k);
   //Any error to report?
   if(error)
      return error;

   //The block cipher operation uses the selected block cipher algorithm
   cipherAlgo = context->cipherAlgo;

   //Generate seedlen bits
   for(i = 0; i < context->seedLen; i += n)
   {
      //Number of bytes to generate at a time
      n = MIN(context->seedLen - i, cipherAlgo->blockSize);

      //Increment counter block
      ctrDrbgIncBlock(context->v, cipherAlgo->blockSize, context->ctrLen);

      //Compute output_block = Block_Encrypt(Key, V)
      cipherAlgo->encryptBlock(&context->cipherContext, context->v,
         block);

      //Set temp = temp || output_block
      osMemcpy(temp + i, block, n);
   }

   //Compute temp = temp + provided_data
   for(i = 0; i < context->seedLen; i++)
   {
      temp[i] ^= providedData[i];
   }

   //Set Key = leftmost(temp, keylen)
   osMemcpy(context->k, temp, context->keyLen);
   //Set V = rightmost(temp, blocklen)
   osMemcpy(context->v, temp + context->keyLen, cipherAlgo->blockSize);

   //Release cipher context
   cipherAlgo->deinit(&context->cipherContext);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Load encryption key
 * @param[in] context Pointer to the CTR_DRBG context
 * @param[in] key Pointer to the Encryption key to load
 * @return Error code
 **/

error_t ctrDrbgLoadKey(CtrDrbgContext *context, const uint8_t *key)
{
   error_t error;
   const CipherAlgo *cipherAlgo;

   //The block cipher operation uses the selected block cipher algorithm
   cipherAlgo = context->cipherAlgo;

#if (DES3_SUPPORT == ENABLED)
   //TDEA cipher algorithm?
   if(cipherAlgo == DES3_CIPHER_ALGO && context->keyLen == 21)
   {
      uint8_t k[24];

      //Convert the 168-bit key to a 192-bit key
      desComputeKeyParity(key, k);
      desComputeKeyParity(key + 7, k + 8);
      desComputeKeyParity(key + 14, k + 16);

      //Load encryption key
      error = cipherAlgo->init(&context->cipherContext, k, sizeof(k));
   }
   else
#endif
   {
      //Load encryption key
      error = cipherAlgo->init(&context->cipherContext, key, context->keyLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Increment counter block
 * @param[in,out] ctr Pointer to the counter block
 * @param[in] blockLen Length of the block, in bytes
 * @param[in] ctrLen Size of the specific part of the block to be incremented
 **/

void ctrDrbgIncBlock(uint8_t *ctr, size_t blockLen, size_t ctrLen)
{
   size_t i;
   uint16_t temp;

   //The function increments the right-most bytes of the block. The remaining
   //left-most bytes remain unchanged
   for(temp = 1, i = 1; i <= ctrLen; i++)
   {
      //Increment the current byte and propagate the carry
      temp += ctr[blockLen - i];
      ctr[blockLen - i] = temp & 0xFF;
      temp >>= 8;
   }
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First input block
 * @param[in] b Second input block
 * @param[in] n Length of the block, in bytes
 **/

void ctrDrbgXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
{
   size_t i;

   //Perform XOR operation
   for(i = 0; i < n; i++)
   {
      x[i] = a[i] ^ b[i];
   }
}

#endif
