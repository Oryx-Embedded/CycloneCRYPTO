/**
 * @file parallel_hash.h
 * @brief ParallelHash hash function
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

#ifndef _PARALLEL_HASH_H
#define _PARALLEL_HASH_H

//Dependencies
#include "core/crypto.h"
#include "xof/cshake.h"

//Application specific context
#ifndef PARALLEL_HASH_CONTEXT_PRIVATE
   #define PARALLEL_HASH_CONTEXT_PRIVATE
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ParallelHash algorithm context
 **/

typedef struct
{
   size_t strength;
   size_t blockSize;
   size_t blockPos;
   size_t blockCount;
   size_t hLen;
   CshakeContext cshakeContext1;
   CshakeContext cshakeContext2;
   PARALLEL_HASH_CONTEXT_PRIVATE
} ParallelHashContext;


//ParallelHash related functions
error_t parallelHashCompute(uint_t strength, size_t blockSize,
   const void *data, size_t dataLen, const char_t *custom, size_t customLen,
   uint8_t *digest, size_t digestLen);

error_t parallelHashInit(ParallelHashContext *context, uint_t strength,
   size_t blockSize, const char_t *custom, size_t customLen);

void parallelHashUpdate(ParallelHashContext *context, const void *data,
   size_t length);

void parallelHashFinal(ParallelHashContext *context, uint8_t *digest, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
