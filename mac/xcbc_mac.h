/**
 * @file xcbc_mac.h
 * @brief XCBC-MAC message authentication code
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

#ifndef _XCBC_MAC_H
#define _XCBC_MAC_H

//Dependencies
#include "core/crypto.h"
#include "cipher/cipher_algorithms.h"

//Application specific context
#ifndef XCBC_MAC_PRIVATE_CONTEXT
   #define XCBC_MAC_PRIVATE_CONTEXT
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief XCBC-MAC algorithm context
 **/

typedef struct
{
   const CipherAlgo *cipher;
   CipherContext cipherContext;
   uint8_t k1[MAX_CIPHER_BLOCK_SIZE];
   uint8_t k2[MAX_CIPHER_BLOCK_SIZE];
   uint8_t k3[MAX_CIPHER_BLOCK_SIZE];
   uint8_t buffer[MAX_CIPHER_BLOCK_SIZE];
   size_t bufferLength;
   uint8_t mac[MAX_CIPHER_BLOCK_SIZE];
   XCBC_MAC_PRIVATE_CONTEXT
} XcbcMacContext;


//XCBC-MAC related functions
error_t xcbcMacCompute(const CipherAlgo *cipher, const void *key, size_t keyLen,
   const void *data, size_t dataLen, uint8_t *mac, size_t macLen);

error_t xcbcMacInit(XcbcMacContext *context, const CipherAlgo *cipher,
   const void *key, size_t keyLen);

void xcbcMacReset(XcbcMacContext *context);
void xcbcMacUpdate(XcbcMacContext *context, const void *data, size_t dataLen);
error_t xcbcMacFinal(XcbcMacContext *context, uint8_t *mac, size_t macLen);
void xcbcMacDeinit(XcbcMacContext *context);

void xcbcMacXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
