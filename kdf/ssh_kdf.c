/**
 * @file ssh_kdf.c
 * @brief SSH key derivation function
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
#include "kdf/ssh_kdf.h"
#include "hash/hash_algorithms.h"

//Check crypto library configuration
#if (SSH_KDF_SUPPORT == ENABLED)


/**
 * @brief SSH key derivation function
 * @param[in] hashAlgo Underlying hash function
 * @param[in] k Shared secret K (encoded as an SSH mpint)
 * @param[in] kLen Length of the shared secret, in bytes
 * @param[in] h Exchange hash H
 * @param[in] hLen Length of the exchange hash, in bytes
 * @param[in] sessionId Session identifier
 * @param[in] sessionIdLen Length of the session identifier, in bytes
 * @param[in] x A single byte ('A' to 'F') selecting the derived key
 * @param[out] output Pointer to the derived key
 * @param[in] outputLen Desired output length, in bytes
 * @return Error code
 **/

error_t sshKdf(const HashAlgo *hashAlgo, const uint8_t *k, size_t kLen,
   const uint8_t *h, size_t hLen, const uint8_t *sessionId,
   size_t sessionIdLen, uint8_t x, uint8_t *output, size_t outputLen)
{
   size_t i;
   size_t n;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //Check parameters
   if(hashAlgo == NULL || k == NULL || h == NULL || sessionId == NULL ||
      output == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hashAlgo->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Compute K(1) = HASH(K || H || X || session_id)
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, k, kLen);
   hashAlgo->update(hashContext, h, hLen);
   hashAlgo->update(hashContext, &x, sizeof(x));
   hashAlgo->update(hashContext, sessionId, sessionIdLen);
   hashAlgo->final(hashContext, digest);

   //Key data must be taken from the beginning of the hash output
   for(n = 0; n < hashAlgo->digestSize && n < outputLen; n++)
   {
      output[n] = digest[n];
   }

   //If the key length needed is longer than the output of the HASH, the key
   //is extended by computing HASH of the concatenation of K and H and the
   //entire key so far, and appending the resulting bytes to the key
   while(n < outputLen)
   {
      //Compute K(n + 1) = HASH(K || H || K(1) || ... || K(n))
      hashAlgo->init(hashContext);
      hashAlgo->update(hashContext, k, kLen);
      hashAlgo->update(hashContext, h, hLen);
      hashAlgo->update(hashContext, output, n);
      hashAlgo->final(hashContext, digest);

      //This process is repeated until enough key material is available
      for(i = 0; i < hashAlgo->digestSize && n < outputLen; i++, n++)
      {
         output[n] = digest[i];
      }
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hashContext);
#endif

   //Successful processing
   return NO_ERROR;
}

#endif
