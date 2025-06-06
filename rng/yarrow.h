/**
 * @file yarrow.h
 * @brief Yarrow PRNG
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

#ifndef _YARROW_H
#define _YARROW_H

//Dependencies
#include "core/crypto.h"
#include "cipher/aes.h"
#include "hash/sha256.h"

//Common interface for PRNG algorithms
#define YARROW_PRNG_ALGO (&yarrowPrngAlgo)

//Pool identifiers
#define YARROW_FAST_POOL_ID 0
#define YARROW_SLOW_POOL_ID 1

//Yarrow PRNG parameters
#define YARROW_N 3
#define YARROW_K 2
#define YARROW_PG 10
#define YARROW_FAST_THRESHOLD 100
#define YARROW_SLOW_THRESHOLD 160

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Yarrow PRNG context
 **/

typedef struct
{
   OsMutex mutex;                    ///<Mutex preventing simultaneous access to the PRNG state
   bool_t ready;                     ///<This flag tells whether the PRNG has been properly seeded
   uint_t currentPool[YARROW_N];     ///<TCurrent pool identifier
   Sha256Context fastPool;           ///<TFast pool
   size_t fastPoolEntropy[YARROW_N]; ///<TEntropy estimation (fast pool)
   Sha256Context slowPool;           ///<TSlow pool
   size_t slowPoolEntropy[YARROW_N]; ///<TEntropy estimation (slow pool)
   AesContext cipherContext;         ///<TCipher context
   uint8_t key[32];                  ///<TCurrent key
   uint8_t counter[16];              ///<TCounter block
   size_t blockCount;                ///<TNumber of blocks that have been generated
} YarrowContext;


//Yarrow related constants
extern const PrngAlgo yarrowPrngAlgo;

//Yarrow related functions
error_t yarrowInit(YarrowContext *context);

error_t yarrowSeed(YarrowContext *context, const uint8_t *input, size_t length);

error_t yarrowAddEntropy(YarrowContext *context, uint_t source,
   const uint8_t *input, size_t length, size_t entropy);

error_t yarrowGenerate(YarrowContext *context, uint8_t *output, size_t length);

void yarrowGenerateBlock(YarrowContext *context, uint8_t *output);
void yarrowFastReseed(YarrowContext *context);
void yarrowSlowReseed(YarrowContext *context);

void yarrowDeinit(YarrowContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
