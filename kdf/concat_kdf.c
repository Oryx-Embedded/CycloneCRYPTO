/**
 * @file concat_kdf.c
 * @brief Concat KDF (Concatenation Key Derivation Function)
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
 * @section Description
 *
 * Concat KDF is a key derivation function defined by NIST SP 800-56A
 * revision 1, section 5.8.1
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "kdf/pbkdf.h"
#include "mac/hmac.h"

//Check crypto library configuration
#if (CONCAT_KDF_SUPPORT == ENABLED)


/**
 * @brief Concat KDF key derivation function
 * @param[in] hash Underlying hash function
 * @param[in] z Shared secret Z
 * @param[in] zLen Length in octets of the shared secret Z
 * @param[in] otherInfo Context-specific information (optional parameter)
 * @param[in] otherInfoLen Length in octets of the context-specific information
 * @param[out] dk Derived keying material
 * @param[in] dkLen Length in octets of the keying material to be generated
 * @return Error code
 **/

error_t concatKdf(const HashAlgo *hash, const uint8_t *z, size_t zLen,
   const uint8_t *otherInfo, size_t otherInfoLen, uint8_t *dk, size_t dkLen)
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
   if(hash == NULL || z == NULL || dk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The OtherInfo parameter is optional
   if(otherInfo == NULL && otherInfoLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Derive the keying material
   for(i = 1; dkLen > 0; i++)
   {
      //Encode the counter as a 32-bit big-endian string
      STORE32BE(i, counter);

      //Compute H(counter || Z || OtherInfo)
      hash->init(hashContext);
      hash->update(hashContext, counter, sizeof(uint32_t));
      hash->update(hashContext, z, zLen);

      //The OtherInfo parameter is optional
      if(otherInfoLen > 0)
      {
         hash->update(hashContext, otherInfo, otherInfoLen);
      }

      //Finalize hash calculation
      hash->final(hashContext, digest);

      //Number of octets in the current block
      n = MIN(dkLen, hash->digestSize);
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
