/**
 * @file hash_drbg.c
 * @brief Hash_DRBG pseudorandom number generator
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
#include "rng/hash_drbg.h"
#include "debug.h"

//Check crypto library configuration
#if (HASH_DRBG_SUPPORT == ENABLED)

//Common interface for PRNG algorithms
const PrngAlgo hashDrbgPrngAlgo =
{
   "Hash_DRBG",
   sizeof(HashDrbgContext),
   (PrngAlgoInit) NULL,
   (PrngAlgoSeed) hashDrbgSeed,
   (PrngAlgoReseed) hashDrbgReseed,
   (PrngAlgoGenerate) hashDrbgGenerate,
   (PrngAlgoDeinit) hashDrbgDeinit
};


/**
 * @brief Initialize PRNG context
 * @param[in] context Pointer to the Hash_DRBG context to initialize
 * @param[in] hashAlgo Approved hash function
 * @return Error code
 **/

error_t hashDrbgInit(HashDrbgContext *context, const HashAlgo *hashAlgo)
{
   //Check parameters
   if(context == NULL || hashAlgo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the internal state
   osMemset(context, 0, sizeof(HashDrbgContext));

   //Create a mutex to prevent simultaneous access to the PRNG state
   if(!osCreateMutex(&context->mutex))
   {
      //Failed to create mutex
      return ERROR_OUT_OF_RESOURCES;
   }

   //The Hash_DRBG requires the use of a hash function during the instantiate,
   //reseed and generate functions. The same hash function shall be used
   //throughout a Hash_DRBG instantiation
   context->hashAlgo = hashAlgo;

   //Determine the security strength (refer to SP 800-57, section 5.6.1.2)
   if(hashAlgo->digestSize <= 20)
   {
      context->securityStrength = 16;
   }
   else if(hashAlgo->digestSize <= 28)
   {
      context->securityStrength = 24;
   }
   else
   {
      context->securityStrength = 32;
   }

   //Determine the seed length (refer to SP 800-90A, section 10.1)
   if(hashAlgo->digestSize <= 32)
   {
      context->seedLen = 55;
   }
   else
   {
      context->seedLen = 111;
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Seed the PRNG state
 * @param[in] context Pointer to the Hash_DRBG context
 * @param[in] seed String of bits obtained from the randomness source
 * @param[in] length Length of the string, in bytes
 * @return Error code
 **/

error_t hashDrbgSeed(HashDrbgContext *context, const uint8_t *seed,
   size_t length)
{
   //Seeding process
   return hashDrbgSeedEx(context, seed, length, NULL, 0, NULL, 0);
}


/**
 * @brief Seed the PRNG state (with nonce and personalization string)
 * @param[in] context Pointer to the Hash_DRBG context
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

error_t hashDrbgSeedEx(HashDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *nonce, size_t nonceLen,
   const uint8_t *personalizationString, size_t personalizationStringLen)
{
   uint8_t k;
   DataChunk input[3];

   //Check parameters
   if(context == NULL || entropyInput == NULL)
      return ERROR_INVALID_PARAMETER;

   //The nonce parameter is optional
   if(nonce == NULL && nonceLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The personalization_string parameter is optional
   if(personalizationString == NULL && personalizationStringLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The Hash_DRBG requires the use of a hash function during the instantiate,
   //reseed and generate functions. The same hash function shall be used
   //throughout a Hash_DRBG instantiation
   if(context->hashAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //The entropy input shall have entropy that is equal to or greater than the
   //security strength of the instantiation
   if(entropyInputLen < context->securityStrength)
      return ERROR_INVALID_PARAMETER;

   //If an implementation utilizes a nonce in the construction of a seed during
   //instantiation, the length of the nonce shall be at least half the maximum
   //security strength supported. Per allowances in SP 800-90A, the length of a
   //nonce may be less than 1/2 the maximum security strength supported as long
   //as the entropy input length + the nonce length >= 3/2 security strength
   if((entropyInputLen + nonceLen) < (3 * context->securityStrength / 2))
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Let seed_material = entropy_input || nonce || personalization_string
   input[0].buffer = entropyInput;
   input[0].length = entropyInputLen;
   input[1].buffer = nonce;
   input[1].length = nonceLen;
   input[2].buffer = personalizationString;
   input[2].length = personalizationStringLen;

   //Compute V = Hash_df(seed_material, seedlen)
   hashDf(context, input, 3, context->v, context->seedLen);

   //Constant byte 0x00
   k = 0;

   //Precede V with a byte of zeros
   input[0].buffer = &k;
   input[0].length = sizeof(k);
   input[1].buffer = context->v;
   input[1].length = context->seedLen;

   //Compute C = Hash_df((0x00 || V), seedlen)
   hashDf(context, input, 2, context->c, context->seedLen);

   //Reset reseed_counter
   context->reseedCounter = 1;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Reseed the PRNG state
 * @param[in] context Pointer to the Hash_DRBG context
 * @param[in] seed String of bits obtained from the randomness source
 * @param[in] length Length of the string, in bytes
 * @return Error code
 **/

error_t hashDrbgReseed(HashDrbgContext *context, const uint8_t *seed,
   size_t length)
{
   //Reseeding process
   return hashDrbgReseedEx(context, seed, length, NULL, 0);
}


/**
 * @brief Reseed the PRNG state (with additional input)
 * @param[in] context Pointer to the Hash_DRBG context
 * @param[in] entropyInput String of bits obtained from the randomness source
 * @param[in] entropyInputLen Length of the string, in bytes
 * @param[in] additionalInput Additional input string received from the
 *   consuming application
 * @param[in] additionalInputLen Length of the additional input string, in bytes
 * @return Error code
 **/

error_t hashDrbgReseedEx(HashDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *additionalInput,
   size_t additionalInputLen)
{
   uint8_t k;
   DataChunk input[4];
   uint8_t seed[HASH_DRBG_MAX_SEED_LEN];

   //Check parameters
   if(context == NULL || entropyInput == NULL)
      return ERROR_INVALID_PARAMETER;

   //The additional_input parameter is optional
   if(additionalInput == NULL && additionalInputLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The Hash_DRBG requires the use of a hash function during the instantiate,
   //reseed and generate functions. The same hash function shall be used
   //throughout a Hash_DRBG instantiation
   if(context->hashAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //Check whether the DRBG has been properly instantiated
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //The entropy input shall have entropy that is equal to or greater than the
   //security strength of the instantiation
   if(entropyInputLen < context->securityStrength)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Constant byte 0x01
   k = 1;

   //Let seed_material = 0x01 || V || entropy_input || additional_input
   input[0].buffer = &k;
   input[0].length = sizeof(k);
   input[1].buffer = context->v;
   input[1].length = context->seedLen;
   input[2].buffer = entropyInput;
   input[2].length = entropyInputLen;
   input[3].buffer = additionalInput;
   input[3].length = additionalInputLen;

   //Compute seed = Hash_df(seed_material, seedlen)
   hashDf(context, input, 4, seed, context->seedLen);
   //Set V = seed
   osMemcpy(context->v, seed, context->seedLen);

   //Constant byte 0x00
   k = 0;

   //Precede V with a byte of zeros
   input[0].buffer = &k;
   input[0].length = sizeof(k);
   input[1].buffer = context->v;
   input[1].length = context->seedLen;

   //Compute C = Hash_df((0x00 || V), seedlen)
   hashDf(context, input, 2, context->c, context->seedLen);

   //Reset reseed_counter
   context->reseedCounter = 1;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Generate pseudorandom data
 * @param[in] context Pointer to the Hash_DRBG context
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] length Requested number of bytes
 * @return Error code
 **/

error_t hashDrbgGenerate(HashDrbgContext *context, uint8_t *output,
   size_t length)
{
   //Generation process
   return hashDrbgGenerateEx(context, NULL, 0, output, length);
}


/**
 * @brief Generate pseudorandom data (with additional input)
 * @param[in] context Pointer to the Hash_DRBG context
 * @param[in] additionalInput Additional input string received from the
 *   consuming application
 * @param[in] additionalInputLen Length of the additional input string, in bytes
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] outputLen Requested number of bytes
 * @return Error code
 **/

error_t hashDrbgGenerateEx(HashDrbgContext *context,
   const uint8_t *additionalInput, size_t additionalInputLen, uint8_t *output,
   size_t outputLen)
{
   uint8_t k;
   uint8_t buffer[8];
   uint8_t t[HASH_DRBG_MAX_SEED_LEN];
   const HashAlgo *hashAlgo;
   HashContext *hashContext;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The additional_input parameter is optional
   if(additionalInput == NULL && additionalInputLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The Hash_DRBG requires the use of a hash function during the instantiate,
   //reseed and generate functions. The same hash function shall be used
   //throughout a Hash_DRBG instantiation
   if(context->hashAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //A DRBG shall be instantiated prior to the generation of pseudorandom bits
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //If reseed_counter > reseed_interval, then return an indication that a
   //reseed is required
   if(context->reseedCounter > HASH_DRBG_MAX_RESEED_INTERVAL)
      return ERROR_RESEED_REQUIRED;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //The Hash_DRBG requires the use of a hash function
   hashAlgo = context->hashAlgo;
   //Point to the hash context
   hashContext = &context->hashContext;

   //The length of the additional input string may be zero
   if(additionalInputLen > 0)
   {
      //Constant byte 0x02
      k = 2;

      //Compute w = Hash(0x02 || V || additional_input)
      hashAlgo->init(hashContext);
      hashAlgo->update(hashContext, &k, sizeof(k));
      hashAlgo->update(hashContext, context->v, context->seedLen);
      hashAlgo->update(hashContext, additionalInput, additionalInputLen);
      hashAlgo->final(hashContext, t);

      //Compute V = (V + w) mod 2^seedlen
      hashDrbgAdd(context->v, context->seedLen, t, hashAlgo->digestSize);
   }

   //Compute Hashgen(requested_number_of_bits, V)
   hashGen(context, output, outputLen);

   //Constant byte 0x03
   k = 3;

   //Compute H = Hash(0x03 || V)
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, &k, sizeof(k));
   hashAlgo->update(hashContext, context->v, context->seedLen);
   hashAlgo->final(hashContext, t);

   //Format reseed_counter as a 64-bit string
   STORE64BE(context->reseedCounter, buffer);

   //Compute V = (V + H + C + reseed_counter) mod 2^seedlen
   hashDrbgAdd(context->v, context->seedLen, t, hashAlgo->digestSize);
   hashDrbgAdd(context->v, context->seedLen, context->c, context->seedLen);
   hashDrbgAdd(context->v, context->seedLen, buffer, sizeof(buffer));

   //Increment reseed_counter
   context->reseedCounter++;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release PRNG context
 * @param[in] context Pointer to the Hash_DRBG context
 **/

void hashDrbgDeinit(HashDrbgContext *context)
{
   //Valid Hash_DRBG context?
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteMutex(&context->mutex);

      //Erase the contents of the internal state
      osMemset(context, 0, sizeof(HashDrbgContext));
   }
}


/**
 * @brief Hash derivation function
 * @param[in] context Pointer to the Hash_DRBG context
 * @param[in] input The string to be hashed
 * @param[in] inputLen Number of data chunks representing the input
 * @param[out] output Buffer where to store the output value
 * @param[out] outputLen The number of bytes to be returned
 **/

void hashDf(HashDrbgContext *context, const DataChunk *input, uint_t inputLen,
   uint8_t *output, size_t outputLen)
{
   size_t i;
   size_t n;
   uint8_t counter;
   uint8_t buffer[4];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
   const HashAlgo *hashAlgo;
   HashContext *hashContext;

   //The Hash_DRBG requires the use of a hash function
   hashAlgo = context->hashAlgo;
   //Point to the hash context
   hashContext = &context->hashContext;

   //Format no_of_bits_to_return as a 32-bit string
   STORE32BE(outputLen * 8, buffer);

   //Generate the requested number of bytes
   for(counter = 1; outputLen > 0; counter++)
   {
      //Number of bytes to generate at a time
      n = MIN(outputLen, hashAlgo->digestSize);

      //Compute Hash (counter || no_of_bits_to_return || input_string)
      hashAlgo->init(hashContext);
      hashAlgo->update(hashContext, &counter, sizeof(counter));
      hashAlgo->update(hashContext, buffer, sizeof(buffer));

      for(i = 0; i < inputLen; i++)
      {
         hashAlgo->update(hashContext, input[i].buffer, input[i].length);
      }

      hashAlgo->final(hashContext, digest);

      //Copy data to the output buffer
      osMemcpy(output, digest, n);

      //Next output block
      output += n;
      outputLen -= n;
   }
}


/**
 * @brief Hash generation sub function
 * @param[in] context Pointer to the Hash_DRBG context
 * @param[out] output Buffer where to store the output value
 * @param[out] outputLen The number of bytes to be returned
 **/

void hashGen(HashDrbgContext *context, uint8_t *output, size_t outputLen)
{
   size_t n;
   uint8_t data[HASH_DRBG_MAX_SEED_LEN];
   uint8_t w[MAX_HASH_DIGEST_SIZE];
   const HashAlgo *hashAlgo;
   HashContext *hashContext;

   //The Hash_DRBG requires the use of a hash function
   hashAlgo = context->hashAlgo;
   //Point to the hash context
   hashContext = &context->hashContext;

   //Let data = V
   osMemcpy(data, context->v, context->seedLen);

   //Generate the requested number of bytes
   while(outputLen > 0)
   {
      //Number of bytes to generate at a time
      n = MIN(outputLen, hashAlgo->digestSize);

      //Compute w = Hash(data)
      hashAlgo->init(hashContext);
      hashAlgo->update(hashContext, data, context->seedLen);
      hashAlgo->final(hashContext, w);

      //Copy data to the output buffer
      osMemcpy(output, w, n);

      //Compute data = (data + 1) mod 2^seedlen
      hashDrbgInc(data, context->seedLen);

      //Next output block
      output += n;
      outputLen -= n;
   }
}


/**
 * @brief Add blocks
 * @param[in,out] a Pointer to the first block
 * @param[in] aLen Length of the first block, in bytes
 * @param[in] b Pointer to the second block
 * @param[in] bLen Length of the second block, in bytes
 **/

void hashDrbgAdd(uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen)
{
   size_t i;
   uint16_t temp;

   //Compute A = A + B
   for(temp = 0, i = 1; i <= aLen; i++)
   {
      //Add the current bytes and propagate the carry
      temp += a[aLen - i];
      temp += (i <= bLen) ? b[bLen - i] : 0;
      a[aLen - i] = temp & 0xFF;
      temp >>= 8;
   }
}


/**
 * @brief Increment block
 * @param[in] a Pointer to the block to be incremented
 * @param[in] aLen Length of the block, in bytes
 **/

void hashDrbgInc(uint8_t *a, size_t aLen)
{
   size_t i;
   uint16_t temp;

   //Compute A = A + 1
   for(temp = 1, i = 1; i <= aLen; i++)
   {
      //Increment the current byte and propagate the carry
      temp += a[aLen - i];
      a[aLen - i] = temp & 0xFF;
      temp >>= 8;
   }
}

#endif
