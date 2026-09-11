/**
 * @file x963_kdf.c
 * @brief ANSI X9.63 key derivation function
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
 * @section Description
 *
 * The ANSI X9.63 KDF key derivation function is a simple construct based on a
 * one-way hash function described in American National Standard X9.63
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "kdf/x963_kdf.h"
#include "hash/hash_algorithms.h"

//Check crypto library configuration
#if (X963_KDF_SUPPORT == ENABLED)


/**
 * @brief ANSI X9.63 key derivation function
 * @param[in] hashAlgo Underlying hash function
 * @param[in] z Shared secret Z
 * @param[in] zLen Length of the shared secret Z, in bytes
 * @param[in] sharedInfo Shared information (optional parameter)
 * @param[in] sharedInfoLen Length of the shared information, in bytes
 * @param[out] dk Derived keying material
 * @param[in] dkLen Length of the keying material to be generated, in bytes
 * @return Error code
 **/

error_t x963Kdf(const HashAlgo *hashAlgo, const uint8_t *z, size_t zLen,
   const uint8_t *sharedInfo, size_t sharedInfoLen, uint8_t *dk, size_t dkLen)
{
   size_t n;
   uint32_t i;
   uint8_t counter[4];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || z == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The SharedInfo parameter is optional
   if(sharedInfo == NULL && sharedInfoLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hashAlgo->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Derive the keying material
   for(i = 1; dkLen > 0; i++)
   {
      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Compute Hash(Z || Counter || SharedInfo)
      hashAlgo->init(hashContext);
      hashAlgo->update(hashContext, z, zLen);
      hashAlgo->update(hashContext, counter, sizeof(uint32_t));
      hashAlgo->update(hashContext, sharedInfo, sharedInfoLen);
      hashAlgo->final(hashContext, digest);

      //Number of octets in the current block
      n = MIN(dkLen, hashAlgo->digestSize);
      //Save the resulting block
      osMemcpy(dk, digest, n);

      //Point to the next block
      dk += n;
      dkLen -= n;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hashContext);
#endif

   //Successful processing
   return NO_ERROR;
}

#endif
