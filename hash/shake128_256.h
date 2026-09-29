/**
 * @file shake128_256.h
 * @brief SHAKE128/256 hash function
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

#ifndef _SHAKE128_256_H
#define _SHAKE128_256_H

//Dependencies
#include "core/crypto.h"
#include "xof/shake.h"

//SHAKE128/256 block size
#define SHAKE128_256_BLOCK_SIZE 168
//SHAKE128/256 digest size
#define SHAKE128_256_DIGEST_SIZE 32
//Minimum length of the padding string
#define SHAKE128_256_MIN_PAD_SIZE 1
//Common interface for hash algorithms
#define SHAKE128_256_HASH_ALGO (&shake128_256HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SHAKE128/256 algorithm context
 **/

typedef ShakeContext Shake128_256Context;


//SHAKE128/256 related constants
extern const HashAlgo shake128_256HashAlgo;

//SHAKE128/256 related functions
error_t shake128_256Compute(const void *data, size_t length, uint8_t *digest);
void shake128_256Init(Shake128_256Context *context);
void shake128_256Update(Shake128_256Context *context, const void *data, size_t length);
void shake128_256Final(Shake128_256Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
