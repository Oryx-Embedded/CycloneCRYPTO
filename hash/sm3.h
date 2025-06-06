/**
 * @file sm3.h
 * @brief SM3 hash function
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

#ifndef _SM3_H
#define _SM3_H

//Dependencies
#include "core/crypto.h"

//Application specific context
#ifndef SM3_PRIVATE_CONTEXT
   #define SM3_PRIVATE_CONTEXT
#endif

//SM3 block size
#define SM3_BLOCK_SIZE 64
//SM3 digest size
#define SM3_DIGEST_SIZE 32
//Minimum length of the padding string
#define SM3_MIN_PAD_SIZE 9
//Common interface for hash algorithms
#define SM3_HASH_ALGO (&sm3HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SM3 algorithm context
 **/

typedef struct
{
   uint32_t h[8];
   union
   {
      uint32_t w[16];
      uint8_t buffer[64];
   };
   size_t size;
   uint64_t totalSize;
   SM3_PRIVATE_CONTEXT
} Sm3Context;


//SM3 related constants
extern const uint8_t SM3_OID[6];
extern const HashAlgo sm3HashAlgo;

//SM3 related functions
error_t sm3Compute(const void *data, size_t length, uint8_t *digest);
void sm3Init(Sm3Context *context);
void sm3Update(Sm3Context *context, const void *data, size_t length);
void sm3Final(Sm3Context *context, uint8_t *digest);
void sm3ProcessBlock(Sm3Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
