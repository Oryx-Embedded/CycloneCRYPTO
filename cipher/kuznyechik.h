/**
 * @file kuznyechik.h
 * @brief Kuznyechik 128bit cipher as specified in GOST R 34-12.2015
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2015  Markku-Juhani O. Saarinen <mjos@iki.fi>
 * Copyright (c) 2017  Vlasta Vesely <vlastavesely@protonmail.ch>
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
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

#ifndef _KUZNYECHIK_H
#define _KUZNYECHIK_H

//Dependencies
#include "core/crypto.h"

//Application specific context
#ifndef KUZNYECHIK_PRIVATE_CONTEXT
   #define KUZNYECHIK_PRIVATE_CONTEXT
#endif

//KUZNYECHIK block size
#define KUZNYECHIK_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define KUZNYECHIK_CIPHER_ALGO (&kuznyechikCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief KUZNYECHIK internal union representing 128-bit data structure.
**/

typedef	union
{
	uint64_t q[2];
	uint8_t  b[16];
} w128_t;


/**
 * @brief KUZNYECHIK algorithm context
 **/

typedef struct
{
   uint_t nr;
   w128_t ek[60];
   w128_t dk[60];
   KUZNYECHIK_PRIVATE_CONTEXT
} KuznyechikContext;

/*
//KUZNYECHIK related constants
extern const uint8_t AES128_ECB_OID[9];
extern const uint8_t AES128_CBC_OID[9];
extern const uint8_t AES128_OFB_OID[9];
extern const uint8_t AES128_CFB_OID[9];
extern const uint8_t AES128_GCM_OID[9];
extern const uint8_t AES128_CCM_OID[9];
extern const uint8_t AES192_ECB_OID[9];
extern const uint8_t AES192_CBC_OID[9];
extern const uint8_t AES192_OFB_OID[9];
extern const uint8_t AES192_CFB_OID[9];
extern const uint8_t AES192_GCM_OID[9];
extern const uint8_t AES192_CCM_OID[9];
extern const uint8_t AES256_ECB_OID[9];
extern const uint8_t AES256_CBC_OID[9];
extern const uint8_t AES256_OFB_OID[9];
extern const uint8_t AES256_CFB_OID[9];
extern const uint8_t AES256_GCM_OID[9];
extern const uint8_t AES256_CCM_OID[9];
*/
extern const CipherAlgo kuznyechikCipherAlgo;

//KUZNYECHIK related functions
error_t kuznyechikInit(KuznyechikContext *context, const uint8_t *key, size_t keyLen);

void kuznyechikEncryptBlock(KuznyechikContext *context, const uint8_t *input, uint8_t *output);

void kuznyechikDecryptBlock(KuznyechikContext *context, const uint8_t *input, uint8_t *output);

void kuznyechikDeinit(KuznyechikContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
