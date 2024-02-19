/**
 * @file streebog.h
 * @brief Streebog-256/512 hash function
 *
 * Streebog-256/512 hash function as specified by GOST R 34.11-2012 and
 * described at https://tools.ietf.org/html/rfc6986
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2013 Alexey Degtyarev <alexey@renatasystems.org>
 * Copyright (c) 2018 Vitaly Chikunov <vt@altlinux.org>
 * Copyright (c) 2024 Valery Novikov <novikov.val@gmail.com>
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
 * @author Valery Novikov <novikov.val@gmail.com>
 * @version 2.4.0
 **/

#ifndef _STREEBOG_H
#define _STREEBOG_H

//Dependencies
#include "core/crypto.h"

//Application specific context
#ifndef STREEBOG256_PRIVATE_CONTEXT
   #define STREEBOG256_PRIVATE_CONTEXT
#endif

//Minimum length of the padding string
#define STREEBOG256_MIN_PAD_SIZE 0		// TODO: ???
#define STREEBOG512_MIN_PAD_SIZE 0		// TODO: ???
//Streebog-256/512 block size
#define STREEBOG_BLOCK_SIZE 64
//Streebog-256 digest size
#define STREEBOG256_DIGEST_SIZE 32
//Streebog-512 digest size
#define STREEBOG512_DIGEST_SIZE 64

#if (STREEBOG256_SUPPORT == ENABLED)
//Common interface for hash algorithms
#define STREEBOG256_HASH_ALGO (&streebog256HashAlgo)
#endif
#if (STREEBOG512_SUPPORT == ENABLED)
//Common interface for hash algorithms
#define STREEBOG512_HASH_ALGO (&streebog512HashAlgo)
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

struct streebog_uint512 {
   uint64_t qword[8];
};


/**
 * @brief Streebog algorithm context
 **/

typedef struct
{
   union
   {
      uint32_t b[16];
      uint8_t digest[64];
	  struct streebog_uint512 hash;
   };
   union
   {
      uint8_t buffer[STREEBOG_BLOCK_SIZE];
	  struct streebog_uint512 m;
   };
   struct streebog_uint512 h;
   struct streebog_uint512 N;
   struct streebog_uint512 Sigma;
   size_t fillsize;
   size_t digest_size;
   STREEBOG256_PRIVATE_CONTEXT
} StreebogContext;


//Streebog related constants
#if (STREEBOG256_SUPPORT == ENABLED)
extern const uint8_t STREEBOG256_OID[8];
extern const HashAlgo streebog256HashAlgo;

error_t streebog256Compute(const void *data, size_t length, uint8_t *digest);
void streebog256Init(StreebogContext *context);
#endif
#if (STREEBOG512_SUPPORT == ENABLED)
extern const uint8_t STREEBOG512_OID[8];
extern const HashAlgo streebog512HashAlgo;

error_t streebog512Compute(const void *data, size_t length, uint8_t *digest);
void streebog512Init(StreebogContext *context);
#endif

//Streebog related functions
void streebogUpdate(StreebogContext *context, const void *data, size_t length);
void streebogFinal(StreebogContext *context, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
