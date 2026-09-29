/**
 * @file one_step_kdf.h
 * @brief One-Step KDF
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CyclSINGLE_CRYPTO Open.
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

#ifndef _ONE_STEP_KDF_H
#define _ONE_STEP_KDF_H

//Dependencies
#include "core/crypto.h"

//Default salt length for KMAC128
#define ONE_STEP_KDF_KMAC128_DEFAULT_SALT_LEN 164
//Default salt length for KMAC256
#define ONE_STEP_KDF_KMAC256_DEFAULT_SALT_LEN 132

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief One-Step KDF auxiliary functions
 **/

typedef enum
{
   ONE_STEP_KDF_TYPE_HASH    = 1,
   ONE_STEP_KDF_TYPE_HMAC    = 2,
   ONE_STEP_KDF_TYPE_KMAC128 = 3,
   ONE_STEP_KDF_TYPE_KMAC256 = 4
} OneStepKdfType;


//One-Step KDF related functions
error_t oneStepKdf(OneStepKdfType type, const HashAlgo *hashAlgo,
   const uint8_t *z, size_t zLen, const uint8_t *salt, size_t saltLen,
   const uint8_t *otherInfo, size_t otherInfoLen, uint8_t *dk, size_t dkLen);

error_t oneStepKdfHash(const HashAlgo *hashAlgo, const uint8_t *z,
   size_t zLen, const uint8_t *otherInfo, size_t otherInfoLen, uint8_t *dk,
   size_t dkLen);

error_t oneStepKdfHmac(const HashAlgo *hashAlgo, const uint8_t *z,
   size_t zLen, const uint8_t *salt, size_t saltLen, const uint8_t *otherInfo,
   size_t otherInfoLen, uint8_t *dk, size_t dkLen);

error_t oneStepKdfKmac(uint_t strength, size_t hLen, const uint8_t *z,
   size_t zLen, const uint8_t *salt, size_t saltLen, const uint8_t *otherInfo,
   size_t otherInfoLen, uint8_t *dk, size_t dkLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
