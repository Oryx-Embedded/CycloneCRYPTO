/**
 * @file hmac_drbg.c
 * @brief HMAC_DRBG pseudorandom number generator
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
#include "core/crypto.h"
#include "rng/hmac_drbg.h"
#include "debug.h"

//Check crypto library configuration
#if (HMAC_DRBG_SUPPORT == ENABLED)


//Common interface for PRNG algorithms
const PrngAlgo hmacDrbgPrngAlgo =
{
   "HMAC_DRBG",
   sizeof(HmacDrbgContext),
   (PrngAlgoInit) NULL,
   (PrngAlgoSeed) hmacDrbgSeed,
   (PrngAlgoReseed) hmacDrbgReseed,
   (PrngAlgoGenerate) hmacDrbgGenerate,
   (PrngAlgoDeinit) hmacDrbgDeinit
};


/**
 * @brief Initialize PRNG context
 * @param[in] context Pointer to the HMAC_DRBG context to initialize
 * @param[in] hashAlgo Approved hash function
 * @return Error code
 **/

error_t hmacDrbgInit(HmacDrbgContext *context, const HashAlgo *hashAlgo)
{
   //Check parameters
   if(context == NULL || hashAlgo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear working state
   osMemset(context, 0, sizeof(HmacDrbgContext));

   //Create a mutex to prevent simultaneous access to the PRNG state
   if(!osCreateMutex(&context->mutex))
   {
      //Failed to create mutex
      return ERROR_OUT_OF_RESOURCES;
   }

   //HMAC_DRBG uses multiple occurrences of an approved keyed hash function,
   //which is based on an approved hash function
   context->hashAlgo = hashAlgo;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Update internal state
 * @param[in] context Pointer to the HMAC_DRBG context
 * @param[in] providedData The data to be used
 * @param[in] providedDataLen Number of data chunks representing the data
 **/

void hmacDrbgUpdate(HmacDrbgContext *context, const DataChunk *providedData,
   uint_t providedDataLen)
{
   uint8_t c;
   size_t i;
   size_t outLen;
   HmacContext *hmacContext;

   //Point to the HMAC context
   hmacContext = &context->hmacContext;
   //Determine the output block length
   outLen = context->hashAlgo->digestSize;

   //Constant byte 0x00
   c = 0;

   //Compute K = HMAC(K, V || 0x00 || provided_data)
   hmacInit(hmacContext, context->hashAlgo, context->k, outLen);
   hmacUpdate(hmacContext, context->v, outLen);
   hmacUpdate(hmacContext, &c, sizeof(c));

   for(i = 0; i < providedDataLen; i++)
   {
      hmacUpdate(hmacContext, providedData[i].buffer,
         providedData[i].length);
   }

   hmacFinal(hmacContext, context->k);

   //Compute V = HMAC(K, V)
   hmacInit(hmacContext, context->hashAlgo, context->k, outLen);
   hmacUpdate(hmacContext, context->v, outLen);
   hmacFinal(hmacContext, context->v);

   //Any data provided?
   if(providedDataLen > 0)
   {
      //Constant byte 0x01
      c = 1;

      //Compute K = HMAC(K, V || 0x01 || provided_data)
      hmacInit(hmacContext, context->hashAlgo, context->k, outLen);
      hmacUpdate(hmacContext, context->v, outLen);
      hmacUpdate(hmacContext, &c, sizeof(c));

      for(i = 0; i < providedDataLen; i++)
      {
         hmacUpdate(hmacContext, providedData[i].buffer,
            providedData[i].length);
      }

      hmacFinal(hmacContext, context->k);

      //Compute V = HMAC(K, V)
      hmacInit(hmacContext, context->hashAlgo, context->k, outLen);
      hmacUpdate(hmacContext, context->v, outLen);
      hmacFinal(hmacContext, context->v);
   }
}


/**
 * @brief Seed the PRNG state
 * @param[in] context Pointer to the HMAC_DRBG context
 * @param[in] input String of bits obtained from the randomness source
 * @param[in] length Length of the string, in bytes
 * @return Error code
 **/

error_t hmacDrbgSeed(HmacDrbgContext *context, const uint8_t *input,
   size_t length)
{
   //Seeding process
   return hmacDrbgSeedEx(context, input, length, NULL, 0, NULL, 0);
}


/**
 * @brief Seed the PRNG state
 * @param[in] context Pointer to the HMAC_DRBG context
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

error_t hmacDrbgSeedEx(HmacDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *nonce, size_t nonceLen,
   const uint8_t *personalizationString, size_t personalizationStringLen)
{
   size_t outLen;
   DataChunk seedMaterial[3];

   //Check parameters
   if(context == NULL || entropyInput == NULL)
      return ERROR_INVALID_PARAMETER;

   //The nonce parameter is optional
   if(nonce == NULL && nonceLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The personalization_string parameter is optional
   if(personalizationString == NULL && personalizationStringLen != 0)
      return ERROR_INVALID_PARAMETER;

   //HMAC_DRBG uses multiple occurrences of an approved keyed hash function,
   //which is based on an approved hash function
   if(context->hashAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //The entropy input shall have entropy that is equal to or greater than the
   //security strength of the instantiation
   if(entropyInputLen < (context->hashAlgo->digestSize / 2))
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Determine the output block length
   outLen = context->hashAlgo->digestSize;

   //Let seed_material = entropy_input || nonce || personalization_string
   seedMaterial[0].buffer = entropyInput;
   seedMaterial[0].length = entropyInputLen;
   seedMaterial[1].buffer = nonce;
   seedMaterial[1].length = nonceLen;
   seedMaterial[2].buffer = personalizationString;
   seedMaterial[2].length = personalizationStringLen;

   //Set Key = 0x00 00...00
   osMemset(context->k, 0x00, outLen);
   //V = 0x01 01...01
   osMemset(context->v, 0x01, outLen);

   //Compute (Key, V) = HMAC_DRBG_Update(seed_material, Key, V)
   hmacDrbgUpdate(context, seedMaterial, arraysize(seedMaterial));

   //Reset reseed_counter
   context->reseedCounter = 1;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Reseed the PRNG state
 * @param[in] context Pointer to the HMAC_DRBG context
 * @param[in] input String of bits obtained from the randomness source
 * @param[in] length Length of the string, in bytes
 * @return Error code
 **/

error_t hmacDrbgReseed(HmacDrbgContext *context, const uint8_t *input,
   size_t length)
{
   //Reseeding process
   return hmacDrbgReseedEx(context, input, length, NULL, 0);
}


/**
 * @brief Reseed the PRNG state
 * @param[in] context Pointer to the HMAC_DRBG context
 * @param[in] entropyInput String of bits obtained from the randomness source
 * @param[in] entropyInputLen Length of the string, in bytes
 * @param[in] additionalInput Additional input string received from the
 *   consuming application
 * @param[in] additionalInputLen Length of the additional input string, in bytes
 * @return Error code
 **/

error_t hmacDrbgReseedEx(HmacDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *additionalInput,
   size_t additionalInputLen)
{
   DataChunk seedMaterial[2];

   //Check parameters
   if(context == NULL || entropyInput == NULL)
      return ERROR_INVALID_PARAMETER;

   //The additional_input parameter is optional
   if(additionalInput == NULL && additionalInputLen != 0)
      return ERROR_INVALID_PARAMETER;

   //HMAC_DRBG uses multiple occurrences of an approved keyed hash function,
   //which is based on an approved hash function
   if(context->hashAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //Check whether the DRBG has been properly instantiated
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //The entropy input shall have entropy that is equal to or greater than the
   //security strength of the instantiation
   if(entropyInputLen < (context->hashAlgo->digestSize / 2))
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Let seed_material = entropy_input || additional_input
   seedMaterial[0].buffer = entropyInput;
   seedMaterial[0].length = entropyInputLen;
   seedMaterial[1].buffer = additionalInput;
   seedMaterial[1].length = additionalInputLen;

   //Compute (Key, V) = HMAC_DRBG_Update(seed_material, Key, V)
   hmacDrbgUpdate(context, seedMaterial, arraysize(seedMaterial));

   //Reset reseed_counter
   context->reseedCounter = 1;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Generate pseudorandom data
 * @param[in] context Pointer to the HMAC_DRBG context
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] length Requested number of bytes
 * @return Error code
 **/

error_t hmacDrbgGenerate(HmacDrbgContext *context, uint8_t *output,
   size_t length)
{
   //Generation process
   return hmacDrbgGenerateEx(context, output, length, NULL, 0);
}


/**
 * @brief Generate pseudorandom data
 * @param[in] context Pointer to the HMAC_DRBG context
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] outputLen Requested number of bytes
 * @param[in] additionalInput Additional input string received from the
 *   consuming application
 * @param[in] additionalInputLen Length of the additional input string, in bytes
 * @return Error code
 **/

error_t hmacDrbgGenerateEx(HmacDrbgContext *context, uint8_t *output,
   size_t outputLen, const uint8_t *additionalInput, size_t additionalInputLen)
{
   size_t n;
   size_t outLen;
   DataChunk providedData[1];
   HmacContext *hmacContext;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The additional_input parameter is optional
   if(additionalInput == NULL && additionalInputLen != 0)
      return ERROR_INVALID_PARAMETER;

   //HMAC_DRBG uses multiple occurrences of an approved keyed hash function,
   //which is based on an approved hash function
   if(context->hashAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //A DRBG shall be instantiated prior to the generation of pseudorandom bits
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //If reseed_counter > reseed_interval, then return an indication that a
   //reseed is required
   if(context->reseedCounter > HMAC_DRBG_MAX_RESEED_INTERVAL)
      return ERROR_RESEED_REQUIRED;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //Point to the HMAC context
   hmacContext = &context->hmacContext;
   //Determine the output block length
   outLen = context->hashAlgo->digestSize;

   //The additional input string is received from the consuming application
   providedData[0].buffer = additionalInput;
   providedData[0].length = additionalInputLen;

   //The length of the additional input string may be zero
   if(additionalInputLen > 0)
   {
      //Compute (Key, V) = HMAC_DRBG_Update(additional_input, Key, V)
      hmacDrbgUpdate(context, providedData, arraysize(providedData));
   }

   //Generate the requested number of bytes
   while(outputLen > 0)
   {
      //Number of bytes to generate at a time
      n = MIN(outputLen, outLen);

      //Calculate V = HMAC(Key, V)
      hmacInit(hmacContext, context->hashAlgo, context->k, outLen);
      hmacUpdate(hmacContext, context->v, outLen);
      hmacFinal(hmacContext, context->v);

      //Copy data to the output buffer
      osMemcpy(output, context->v, n);

      //Next output block
      output += n;
      outputLen -= n;
   }

   //Calculate (Key, V) = HMAC_DRBG_Update(additional_input, Key, V)
   if(additionalInputLen > 0)
   {
      hmacDrbgUpdate(context, providedData, arraysize(providedData));
   }
   else
   {
      hmacDrbgUpdate(context, NULL, 0);
   }

   //Increment reseed_counter
   context->reseedCounter++;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release PRNG context
 * @param[in] context Pointer to the HMAC_DRBG context
 **/

void hmacDrbgDeinit(HmacDrbgContext *context)
{
   //Valid HMAC_DRBG context?
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteMutex(&context->mutex);

      //Clear working state
      osMemset(context, 0, sizeof(HmacDrbgContext));
   }
}

#endif
