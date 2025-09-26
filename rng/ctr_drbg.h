/**
 * @file ctr_drbg.h
 * @brief CTR_DRBG pseudorandom number generator
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

#ifndef _CTR_DRBG_H
#define _CTR_DRBG_H

//Dependencies
#include "core/crypto.h"
#include "cipher/cipher_algorithms.h"

//Maximum length of the key
#define CTR_DRBG_MAX_KEY_LEN 32
//Maximum length of the seed
#define CTR_DRBG_MAX_SEED_LEN 48
//Maximum number of requests between reseeds
#define CTR_DRBG_MAX_RESEED_INTERVAL 281474976710656ULL

//Common interface for PRNG algorithms
#define CTR_DRBG_PRNG_ALGO (&ctrDrbgPrngAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief CTR_DRBG PRNG context
 **/

typedef struct
{
   OsMutex mutex;                    ///<Mutex preventing simultaneous access to the PRNG state
   const CipherAlgo *cipherAlgo;     ///<Cipher function
   CipherContext cipherContext;      ///<Cipher context
   size_t keyLen;                    ///<Key length
   size_t securityStrength;          ///<Security strength
   bool_t df;                        ///<Use key derivation function
   size_t ctrLen;                    ///<Counter length
   size_t seedLen;                   ///<Seed length
   uint8_t v[MAX_CIPHER_BLOCK_SIZE]; ///<Value V
   uint8_t k[CTR_DRBG_MAX_KEY_LEN];  ///<Key
   uint64_t reseedCounter;           ///<Reseed counter
} CtrDrbgContext;


//CTR_DRBG related constants
extern const PrngAlgo ctrDrbgPrngAlgo;

//CTR_DRBG related functions
error_t ctrDrbgInit(CtrDrbgContext *context, const CipherAlgo *cipherAlgo,
   size_t keyLen, bool_t df);

error_t ctrDrbgSeed(CtrDrbgContext *context, const uint8_t *seed,
   size_t length);

error_t ctrDrbgSeedEx(CtrDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *nonce, size_t nonceLen,
   const uint8_t *personalizationString, size_t personalizationStringLen);

error_t ctrDrbgReseed(CtrDrbgContext *context, const uint8_t *seed,
   size_t length);

error_t ctrDrbgReseedEx(CtrDrbgContext *context, const uint8_t *entropyInput,
   size_t entropyInputLen, const uint8_t *additionalInput,
   size_t additionalInputLen);

error_t ctrDrbgGenerate(CtrDrbgContext *context, uint8_t *output,
   size_t length);

error_t ctrDrbgGenerateEx(CtrDrbgContext *context,
   const uint8_t *additionalInput, size_t additionalInputLen, uint8_t *output,
   size_t outputLen);

void ctrDrbgDeinit(CtrDrbgContext *context);

error_t blockCipherDf(CtrDrbgContext *context, const DataChunk *input,
   uint_t inputLen, uint8_t *output, size_t outputLen);

error_t ctrDrbgBcc(CtrDrbgContext *context, const uint8_t *key,
   const DataChunk *data, uint_t dataLen, uint8_t *output);

error_t ctrDrbgUpdate(CtrDrbgContext *context, const uint8_t *providedData,
   size_t providedDataLen);

error_t ctrDrbgLoadKey(CtrDrbgContext *context, const uint8_t *key);

void ctrDrbgIncBlock(uint8_t *ctr, size_t blockLen, size_t ctrLen);
void ctrDrbgXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
