/**
 * @file shake256_512.h
 * @brief SHAKE256/512 hash function
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

#ifndef _SHAKE256_512_H
#define _SHAKE256_512_H

//Dependencies
#include "core/crypto.h"
#include "xof/shake.h"

//SHAKE256/512 block size
#define SHAKE256_512_BLOCK_SIZE 136
//SHAKE256/512 digest size
#define SHAKE256_512_DIGEST_SIZE 64
//Minimum length of the padding string
#define SHAKE256_512_MIN_PAD_SIZE 1
//Common interface for hash algorithms
#define SHAKE256_512_HASH_ALGO (&shake256_512HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SHAKE256/512 algorithm context
 **/

typedef ShakeContext Shake256_512Context;


//SHAKE256/512 related constants
extern const HashAlgo shake256_512HashAlgo;

//SHAKE256/512 related functions
error_t shake256_512Compute(const void *data, size_t length, uint8_t *digest);
void shake256_512Init(Shake256_512Context *context);
void shake256_512Update(Shake256_512Context *context, const void *data, size_t length);
void shake256_512Final(Shake256_512Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
