/**
 * @file kmac_xof.h
 * @brief KMACXOF (KMAC with arbitrary-length output)
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

#ifndef _KMAC_XOF_H
#define _KMAC_XOF_H

//Dependencies
#include "core/crypto.h"
#include "xof/cshake.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief KMACXOF algorithm context
 **/

typedef struct
{
   CshakeContext cshakeContext;
} KmacXofContext;


//KMACXOF related constants
extern const uint8_t KMAC_XOF128_OID[9];
extern const uint8_t KMAC_XOF256_OID[9];

//KMACXOF related functions
error_t kmacXofCompute(uint_t strength, const void *key, size_t keyLen,
   const void *data, size_t dataLen, const char_t *custom, size_t customLen,
   uint8_t *mac, size_t macLen);

error_t kmacXofInit(KmacXofContext *context, uint_t strength, const void *key,
   size_t keyLen, const char_t *custom, size_t customLen);

void kmacXofAbsorb(KmacXofContext *context, const void *input, size_t length);
void kmacXofFinal(KmacXofContext *context);
void kmacXofSqueeze(KmacXofContext *context, uint8_t *output, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
