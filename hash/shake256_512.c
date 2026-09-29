/**
 * @file shake256_512.c
 * @brief SHAKE256/512 hash function
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/shake256_512.h"

//Check crypto library configuration
#if (SHAKE256_512_SUPPORT == ENABLED)

//Common interface for hash algorithms
const HashAlgo shake256_512HashAlgo =
{
   "SHAKE256/512",
   SHAKE256_OID,
   sizeof(SHAKE256_OID),
   sizeof(Shake256_512Context),
   SHAKE256_512_BLOCK_SIZE,
   SHAKE256_512_DIGEST_SIZE,
   SHAKE256_512_MIN_PAD_SIZE,
   TRUE,
   (HashAlgoCompute) shake256_512Compute,
   (HashAlgoInit) shake256_512Init,
   (HashAlgoUpdate) shake256_512Update,
   (HashAlgoFinal) shake256_512Final,
   NULL
};


/**
 * @brief Digest a message using SHAKE256/512
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

__weak_func error_t shake256_512Compute(const void *data, size_t length, uint8_t *digest)
{
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Shake256_512Context *context;
#else
   Shake256_512Context context[1];
#endif

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   if(digest == NULL)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the SHAKE256/512 context
   context = cryptoAllocMem(sizeof(Shake256_512Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the SHAKE256/512 context
   shake256_512Init(context);
   //Digest the message
   shake256_512Update(context, data, length);
   //Finalize the SHAKE256/512 message digest
   shake256_512Final(context, digest);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SHAKE256/512 message digest context
 * @param[in] context Pointer to the SHAKE256/512 context to initialize
 **/

__weak_func void shake256_512Init(Shake256_512Context *context)
{
   //Initialize the SHAKE256 context
   shakeInit(context, 256);
}


/**
 * @brief Update the SHAKE256/512 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHAKE256/512 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

__weak_func void shake256_512Update(Shake256_512Context *context, const void *data, size_t length)
{
   //Absorb the input data
   shakeAbsorb(context, data, length);
}


/**
 * @brief Finish the SHAKE256/512 message digest
 * @param[in] context Pointer to the SHAKE256/512 context
 * @param[out] digest Calculated digest
 **/

__weak_func void shake256_512Final(Shake256_512Context *context, uint8_t *digest)
{
   //Finish absorbing phase
   shakeFinal(context);
   //Extract data from the squeezing phase
   shakeSqueeze(context, digest, SHAKE256_512_DIGEST_SIZE);
}

#endif
