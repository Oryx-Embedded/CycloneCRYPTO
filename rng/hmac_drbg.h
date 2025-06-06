/**
 * @file hmac_drbg.h
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

#ifndef _HMAC_DRBG_H
#define _HMAC_DRBG_H

//Dependencies
#include "core/crypto.h"
#include "mac/hmac.h"

//Maximum number of requests between reseeds
#define HMAC_DRBG_MAX_RESEED_INTERVAL 281474976710656ULL

//Common interface for PRNG algorithms
#define HMAC_DRBG_PRNG_ALGO (&hmacDrbgPrngAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief HMAC_DRBG PRNG context
 **/

typedef struct
{
   OsMutex mutex;                     ///<Mutex preventing simultaneous access to the PRNG state
   const HashAlgo *hashAlgo;          ///<Hash function
   HmacContext hmacContext;           ///<HMAC context
   uint8_t k[MAX_HASH_DIGEST_SIZE];   ///<Key
   uint8_t v[MAX_HASH_DIGEST_SIZE];   ///<Value V
   uint64_t reseedCounter;            ///<Reseed counter
} HmacDrbgContext;


//HMAC_DRBG related constants
extern const PrngAlgo hmacDrbgPrngAlgo;

//HMAC_DRBG related functions
error_t hmacDrbgInit(HmacDrbgContext *context, const HashAlgo *hashAlgo);

void hmacDrbgUpdate(HmacDrbgContext *context, const DataChunk *providedData,
   uint_t providedDataLen);

error_t hmacDrbgSeed(HmacDrbgContext *context, const uint8_t *input,
   size_t length);

error_t hmacDrbgSeedEx(HmacDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *nonce, size_t nonceLen,
   const uint8_t *personalizationString, size_t personalizationStringLen);

error_t hmacDrbgReseed(HmacDrbgContext *context, const uint8_t *input,
   size_t length);

error_t hmacDrbgReseedEx(HmacDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *additionalInput,
   size_t additionalInputLen);

error_t hmacDrbgGenerate(HmacDrbgContext *context, uint8_t *output,
   size_t length);

error_t hmacDrbgGenerateEx(HmacDrbgContext *context, uint8_t *output,
   size_t outputLen, const uint8_t *additionalInput, size_t additionalInputLen);

void hmacDrbgDeinit(HmacDrbgContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
