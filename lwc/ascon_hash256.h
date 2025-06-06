/**
 * @file ascon_hash256.h
 * @brief Ascon-Hash256 hash function
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

#ifndef _ASCON_HASH256_H
#define _ASCON_HASH256_H

//Dependencies
#include "core/crypto.h"
#include "lwc/ascon.h"

//Application specific context
#ifndef ASCON_HASH256_PRIVATE_CONTEXT
   #define ASCON_HASH256_PRIVATE_CONTEXT
#endif

//Ascon-Hash256 block size
#define ASCON_HASH256_BLOCK_SIZE 8
//Ascon-Hash256 digest size
#define ASCON_HASH256_DIGEST_SIZE 32
//Minimum length of the padding string
#define ASCON_HASH256_MIN_PAD_SIZE 0
//Common interface for hash algorithms
#define ASCON_HASH256_HASH_ALGO (&asconHash256HashAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Ascon-Hash256 algorithm context
 **/

typedef struct
{
   AsconState state;
   uint8_t buffer[8];
   size_t length;
} AsconHash256Context;


//Ascon-Hash256 related constants
extern const uint8_t ASCON_HASH256_OID[1];
extern const HashAlgo asconHash256HashAlgo;

//Ascon-Hash256 related functions
error_t asconHash256Compute(const void *data, size_t length, uint8_t *digest);
void asconHash256Init(AsconHash256Context *context);
void asconHash256Update(AsconHash256Context *context, const void *data, size_t length);
void asconHash256Final(AsconHash256Context *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
