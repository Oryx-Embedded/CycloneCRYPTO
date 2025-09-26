/**
 * @file hash_drbg.h
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

#ifndef _HASH_DRBG_H
#define _HASH_DRBG_H

//Dependencies
#include "core/crypto.h"
#include "hash/hash_algorithms.h"

//Maximum seed length
#define HASH_DRBG_MAX_SEED_LEN 111
//Maximum number of requests between reseeds
#define HASH_DRBG_MAX_RESEED_INTERVAL 281474976710656ULL

//Common interface for PRNG algorithms
#define HASH_DRBG_PRNG_ALGO (&hashDrbgPrngAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Hash_DRBG PRNG context
 **/

typedef struct
{
   OsMutex mutex;                     ///<Mutex preventing simultaneous access to the PRNG state
   const HashAlgo *hashAlgo;          ///<Hash function
   HashContext hashContext;           ///<Hash context
   size_t securityStrength;           ///<Security strength
   size_t seedLen;                    ///<Seed length
   uint8_t v[HASH_DRBG_MAX_SEED_LEN]; ///<Value V
   uint8_t c[HASH_DRBG_MAX_SEED_LEN]; ///<Constant C
   uint64_t reseedCounter;            ///<Reseed counter
} HashDrbgContext;


//Hash_DRBG related constants
extern const PrngAlgo hashDrbgPrngAlgo;

//Hash_DRBG related functions
error_t hashDrbgInit(HashDrbgContext *context, const HashAlgo *hashAlgo);

error_t hashDrbgSeed(HashDrbgContext *context, const uint8_t *seed,
   size_t length);

error_t hashDrbgSeedEx(HashDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *nonce, size_t nonceLen,
   const uint8_t *personalizationString, size_t personalizationStringLen);

error_t hashDrbgReseed(HashDrbgContext *context, const uint8_t *seed,
   size_t length);

error_t hashDrbgReseedEx(HashDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *additionalInput,
   size_t additionalInputLen);

error_t hashDrbgGenerate(HashDrbgContext *context, uint8_t *output,
   size_t length);

error_t hashDrbgGenerateEx(HashDrbgContext *context,
   const uint8_t *additionalInput, size_t additionalInputLen, uint8_t *output,
   size_t outputLen);

void hashDrbgDeinit(HashDrbgContext *context);

void hashDf(HashDrbgContext *context, const DataChunk *input, uint_t inputLen,
   uint8_t *output, size_t outputLen);

void hashGen(HashDrbgContext *context, uint8_t *output, size_t outputLen);

void hashDrbgAdd(uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen);
void hashDrbgInc(uint8_t *a, size_t aLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
