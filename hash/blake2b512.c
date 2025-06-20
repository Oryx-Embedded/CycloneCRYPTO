/**
 * @file blake2b512.c
 * @brief BLAKE2b-512 hash function
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
#include "hash/blake2b512.h"

//Check crypto library configuration
#if (BLAKE2B512_SUPPORT == ENABLED)

//BLAKE2b-512 object identifier (1.3.6.1.4.1.1722.12.2.1.16)
const uint8_t BLAKE2B512_OID[11] = {0x43, 0x06, 0x01, 0x04, 0x01, 0x8D, 0x3A, 0x0C, 0x02, 0x01, 0x10};

//Common interface for hash algorithms
const HashAlgo blake2b512HashAlgo =
{
   "BLAKE2b-512",
   BLAKE2B512_OID,
   sizeof(BLAKE2B512_OID),
   sizeof(Blake2b512Context),
   BLAKE2B512_BLOCK_SIZE,
   BLAKE2B512_DIGEST_SIZE,
   BLAKE2B512_MIN_PAD_SIZE,
   FALSE,
   (HashAlgoCompute) blake2b512Compute,
   (HashAlgoInit) blake2b512Init,
   (HashAlgoUpdate) blake2b512Update,
   (HashAlgoFinal) blake2b512Final,
   NULL
};


/**
 * @brief Digest a message using BLAKE2b-512
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t blake2b512Compute(const void *data, size_t length, uint8_t *digest)
{
   //Compute the unkeyed hash with BLAKE2b-512
   return blake2bCompute(NULL, 0, data, length, digest, BLAKE2B512_DIGEST_SIZE);
}


/**
 * @brief Initialize BLAKE2b-512 hash computation
 * @param[in] context Pointer to the BLAKE2b context to initialize
 **/

void blake2b512Init(Blake2b512Context *context)
{
   //Initialize the hashing context
   blake2bInit(context, NULL, 0, BLAKE2B512_DIGEST_SIZE);
}


/**
 * @brief Update BLAKE2b-512 hash computation
 * @param[in] context Pointer to the BLAKE2b context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void blake2b512Update(Blake2b512Context *context, const void *data, size_t length)
{
   //Digest the data
   blake2bUpdate(context, data, length);
}


/**
 * @brief Finish BLAKE2b-512 hash computation
 * @param[in] context Pointer to the BLAKE2b context
 * @param[out] digest Calculated digest
 **/

void blake2b512Final(Blake2b512Context *context, uint8_t *digest)
{
   //Generate the message digest
   blake2bFinal(context, digest);
}

#endif
