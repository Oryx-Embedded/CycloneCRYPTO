/**
 * @file sm4.h
 * @brief SM4 encryption algorithm
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

#ifndef _SM4_H
#define _SM4_H

//Dependencies
#include "core/crypto.h"

//Application specific context
#ifndef SM4_PRIVATE_CONTEXT
   #define SM4_PRIVATE_CONTEXT
#endif

//SM4 block size
#define SM4_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define SM4_CIPHER_ALGO (&sm4CipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SM4 algorithm context
 **/

typedef struct
{
   uint_t nr;
   uint32_t rk[32];
   SM4_PRIVATE_CONTEXT
} Sm4Context;


//SM4 related constants
extern const uint8_t SM4_CBC_OID[8];
extern const uint8_t SM4_ECB_OID[8];
extern const uint8_t SM4_CBC_OID[8];
extern const uint8_t SM4_OFB_OID[8];
extern const uint8_t SM4_CFB_OID[8];
extern const uint8_t SM4_CTR_OID[8];
extern const uint8_t SM4_GCM_OID[8];
extern const uint8_t SM4_CCM_OID[8];
extern const uint8_t SM4_XTS_OID[8];
extern const CipherAlgo sm4CipherAlgo;

//SM4 related functions
error_t sm4Init(Sm4Context *context, const uint8_t *key, size_t keyLen);

void sm4EncryptBlock(Sm4Context *context, const uint8_t *input,
   uint8_t *output);

void sm4DecryptBlock(Sm4Context *context, const uint8_t *input,
   uint8_t *output);

void sm4Deinit(Sm4Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
