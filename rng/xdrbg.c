/**
 * @file xdrbg.c
 * @brief XDRBG pseudorandom number generator
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
#include "rng/xdrbg.h"
#include "debug.h"

//Check crypto library configuration
#if (XDRBG_SUPPORT == ENABLED)

//Common interface for PRNG algorithms
const PrngAlgo xdrbgPrngAlgo =
{
   "XDRBG",
   sizeof(XdrbgContext),
   (PrngAlgoInit) NULL,
   (PrngAlgoSeed) xdrbgSeed,
   (PrngAlgoReseed) xdrbgReseed,
   (PrngAlgoGenerate) xdrbgGenerate,
   (PrngAlgoDeinit) xdrbgDeinit
};


/**
 * @brief Initialize PRNG context
 * @param[in] context Pointer to the XDRBG context to initialize
 * @param[in] xofAlgo XOF algorithm
 * @return Error code
 **/

error_t xdrbgInit(XdrbgContext *context, const XofAlgo *xofAlgo)
{
   //Check parameters
   if(context == NULL || xofAlgo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the internal state
   osMemset(context, 0, sizeof(XdrbgContext));

   //Create a mutex to prevent simultaneous access to the PRNG state
   if(!osCreateMutex(&context->mutex))
   {
      //Failed to create mutex
      return ERROR_OUT_OF_RESOURCES;
   }

#if (SHAKE_SUPPORT == ENABLED)
   //SHAKE128 XOF algorithm?
   if(xofAlgo == SHAKE128_XOF_ALGO)
   {
      //Set parameters
      context->xofAlgo = SHAKE128_XOF_ALGO;
      context->securityStrength = 16;
      context->maxOutputLen = 304;
   }
   else
#endif
#if (SHAKE_SUPPORT == ENABLED)
   //SHAKE256 XOF algorithm?
   if(xofAlgo == SHAKE256_XOF_ALGO)
   {
      //Set parameters
      context->xofAlgo = SHAKE256_XOF_ALGO;
      context->securityStrength = 32;
      context->maxOutputLen = 344;
   }
   else
#endif
#if (ASCON_XOF128_SUPPORT == ENABLED)
   //Ascon-XOF128 XOF algorithm?
   if(xofAlgo == ASCON_XOF128_XOF_ALGO)
   {
      //Set parameters
      context->xofAlgo = ASCON_XOF128_XOF_ALGO;
      context->securityStrength = 16;
      context->maxOutputLen = 256;
   }
   else
#endif
   //Unknown XOF algorithm?
   {
      //Report an error
      return ERROR_UNSUPPORTED_ALGO;
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Seed the PRNG state
 * @param[in] context Pointer to the XDRBG context
 * @param[in] seed Seed material
 * @param[in] seedLen Length of the seed material, in bytes
 * @return Error code
 **/

error_t xdrbgSeed(XdrbgContext *context, const uint8_t *seed, size_t length)
{
   //Seeding process
   return xdrbgSeedEx(context, seed, length, NULL, 0);
}


/**
 * @brief Seed the PRNG state (with nonce and personalization string)
 * @param[in] context Pointer to the XDRBG context
 * @param[in] seed Seed material
 * @param[in] seedLen Length of the seed material, in bytes
 * @param[in] alpha Optional data
 * @param[in] alphaLen Length of the additional data, in bytes
 * @return Error code
 **/

error_t xdrbgSeedEx(XdrbgContext *context, const uint8_t *seed, size_t seedLen,
   const uint8_t *alpha, size_t alphaLen)
{
   uint8_t encode;
   const XofAlgo *xofAlgo;
   XofContext *xofContext;

   //Check parameters
   if(context == NULL || seed == NULL)
      return ERROR_INVALID_PARAMETER;

   //The alpha parameter is optional
   if(alpha == NULL && alphaLen != 0)
      return ERROR_INVALID_PARAMETER;

   //XDRBG is a DRBG based on an underlying XOF
   if(context->xofAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //Check the length of the seed
   if(seedLen < (3 * context->securityStrength / 2))
      return ERROR_INVALID_PARAMETER;

   //The additional input string must not be longer than 84 bytes
   if(alphaLen > XDRBG_MAX_ALPHA_LEN)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //XDRBG is intended to be usable with any XOF
   xofAlgo = context->xofAlgo;
   //Point to the XOF context
   xofContext = &context->xofContext;

   //The encoding adds a single byte of stretch
   encode = XDRBG_ENCODE(alphaLen, 0);

   //Initialize internal state
   xofAlgo->init(xofContext);
   xofAlgo->absorb(xofContext, seed, seedLen);
   xofAlgo->absorb(xofContext, alpha, alphaLen);
   xofAlgo->absorb(xofContext, &encode, sizeof(encode));
   xofAlgo->final(xofContext);
   xofAlgo->squeeze(xofContext, context->v, context->securityStrength * 2);

   //Reset reseed_counter
   context->reseedCounter = 1;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Reseed the PRNG state
 * @param[in] context Pointer to the XDRBG context
 * @param[in] seed Seed material
 * @param[in] seedLen Length of the seed material, in bytes
 * @return Error code
 **/

error_t xdrbgReseed(XdrbgContext *context, const uint8_t *seed, size_t length)
{
   //Reseeding process
   return xdrbgReseedEx(context, seed, length, NULL, 0);
}


/**
 * @brief Reseed the PRNG state (with additional input)
 * @param[in] context Pointer to the XDRBG context
 * @param[in] seed Seed material
 * @param[in] seedLen Length of the seed material, in bytes
 * @param[in] alpha Optional data
 * @param[in] alphaLen Length of the additional data, in bytes
 * @return Error code
 **/

error_t xdrbgReseedEx(XdrbgContext *context, const uint8_t *seed,
   size_t seedLen, const uint8_t *alpha, size_t alphaLen)
{
   uint8_t encode;
   const XofAlgo *xofAlgo;
   XofContext *xofContext;

   //Check parameters
   if(context == NULL || seed == NULL)
      return ERROR_INVALID_PARAMETER;

   //The alpha parameter is optional
   if(alpha == NULL && alphaLen != 0)
      return ERROR_INVALID_PARAMETER;

   //XDRBG is a DRBG based on an underlying XOF
   if(context->xofAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //Check whether the DRBG has been properly instantiated
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //Check the length of the seed
   if(seedLen < context->securityStrength)
      return ERROR_INVALID_PARAMETER;

   //The additional input string must not be longer than 84 bytes
   if(alphaLen > XDRBG_MAX_ALPHA_LEN)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //XDRBG is intended to be usable with any XOF
   xofAlgo = context->xofAlgo;
   //Point to the XOF context
   xofContext = &context->xofContext;

   //The encoding adds a single byte of stretch
   encode = XDRBG_ENCODE(alphaLen, 1);

   //Update internal state
   xofAlgo->init(xofContext);
   xofAlgo->absorb(xofContext, context->v, context->securityStrength * 2);
   xofAlgo->absorb(xofContext, seed, seedLen);
   xofAlgo->absorb(xofContext, alpha, alphaLen);
   xofAlgo->absorb(xofContext, &encode, sizeof(encode));
   xofAlgo->final(xofContext);
   xofAlgo->squeeze(xofContext, context->v, context->securityStrength * 2);

   //Reset reseed_counter
   context->reseedCounter = 1;

   //Release exclusive access to the PRNG state
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Generate pseudorandom data
 * @param[in] context Pointer to the XDRBG context
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] length Requested number of bytes
 * @return Error code
 **/

error_t xdrbgGenerate(XdrbgContext *context, uint8_t *output, size_t length)
{
   //Generation process
   return xdrbgGenerateEx(context, NULL, 0, output, length);
}


/**
 * @brief Generate pseudorandom data (with additional input)
 * @param[in] context Pointer to the XDRBG context
 * @param[in] alpha Optional data
 * @param[in] alphaLen Length of the additional data, in bytes
 * @param[out] output Buffer where to store the pseudorandom bytes
 * @param[in] outputLen Requested number of bytes
 * @return Error code
 **/

error_t xdrbgGenerateEx(XdrbgContext *context, const uint8_t *alpha,
   size_t alphaLen, uint8_t *output, size_t outputLen)
{
   size_t n;
   uint8_t encode;
   const XofAlgo *xofAlgo;
   XofContext *xofContext;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The alpha parameter is optional
   if(alpha == NULL && alphaLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The additional input string must not be longer than 84 bytes
   if(alphaLen > XDRBG_MAX_ALPHA_LEN)
      return ERROR_INVALID_PARAMETER;

   //XDRBG is a DRBG based on an underlying XOF
   if(context->xofAlgo == NULL)
      return ERROR_PRNG_NOT_READY;

   //A DRBG shall be instantiated prior to the generation of pseudorandom bits
   if(context->reseedCounter == 0)
      return ERROR_PRNG_NOT_READY;

   //Acquire exclusive access to the PRNG state
   osAcquireMutex(&context->mutex);

   //XDRBG is intended to be usable with any XOF
   xofAlgo = context->xofAlgo;
   //Point to the XOF context
   xofContext = &context->xofContext;

   //The encoding adds a single byte of stretch
   encode = XDRBG_ENCODE(alphaLen, 2);

   //Generate the requested number of bytes
   while(outputLen > 0)
   {
      //Number of bytes to generate at a time
      n = MIN(outputLen, context->maxOutputLen);

      //Update internal state
      xofAlgo->init(xofContext);
      xofAlgo->absorb(xofContext, context->v, context->securityStrength * 2);
      xofAlgo->absorb(xofContext, alpha, alphaLen);
      xofAlgo->absorb(xofContext, &encode, sizeof(encode));
      xofAlgo->final(xofContext);
      xofAlgo->squeeze(xofContext, context->v, context->securityStrength * 2);

      //Generate output string
      xofAlgo->squeeze(xofContext, output, n);

      //Advance data pointer
      output += n;
      outputLen -= n;
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
 * @param[in] context Pointer to the XDRBG context
 **/

void xdrbgDeinit(XdrbgContext *context)
{
   //Valid XDRBG context?
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteMutex(&context->mutex);

      //Erase the contents of the internal state
      osMemset(context, 0, sizeof(XdrbgContext));
   }
}

#endif
