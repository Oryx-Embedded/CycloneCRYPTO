/**
 * @file kmac.h
 * @brief KMAC (Keccak Message Authentication Code)
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

#ifndef _KMAC_H
#define _KMAC_H

//Dependencies
#include "core/crypto.h"
#include "xof/cshake.h"

//Application specific context
#ifndef KMAC_PRIVATE_CONTEXT
   #define KMAC_PRIVATE_CONTEXT
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief KMAC algorithm context
 **/

typedef struct
{
   CshakeContext cshakeContext;
   KMAC_PRIVATE_CONTEXT
} KmacContext;


//KMAC related constants
extern const uint8_t KMAC128_OID[9];
extern const uint8_t KMAC256_OID[9];

//KMAC related functions
error_t kmacCompute(uint_t strength, const void *key, size_t keyLen,
   const void *data, size_t dataLen, const char_t *custom, size_t customLen,
   uint8_t *mac, size_t macLen);

error_t kmacInit(KmacContext *context, uint_t strength, const void *key,
   size_t keyLen, const char_t *custom, size_t customLen);

void kmacUpdate(KmacContext *context, const void *data, size_t dataLen);
error_t kmacFinal(KmacContext *context, uint8_t *mac, size_t macLen);
void kmacDeinit(KmacContext *context);

void kmacRightEncode(size_t value, uint8_t *buffer, size_t *length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
