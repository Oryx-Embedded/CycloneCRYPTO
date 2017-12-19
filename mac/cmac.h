/**
 * @file cmac.h
 * @brief CMAC (Cipher-based Message Authentication Code)
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.8.0
 **/

#ifndef _CMAC_H
#define _CMAC_H

//Dependencies
#include "core/crypto.h"

//RC6 support?
#if (RC6_SUPPORT == ENABLED)
   #include "cipher/rc6.h"
#endif

//IDEA support?
#if (IDEA_SUPPORT == ENABLED)
   #include "cipher/idea.h"
#endif

//DES support?
#if (DES_SUPPORT == ENABLED)
   #include "cipher/des.h"
#endif

//Triple DES support?
#if (DES3_SUPPORT == ENABLED)
   #include "cipher/des3.h"
#endif

//AES support?
#if (AES_SUPPORT == ENABLED)
   #include "cipher/aes.h"
#endif

//Camellia support?
#if (CAMELLIA_SUPPORT == ENABLED)
   #include "cipher/camellia.h"
#endif

//SEED support?
#if (SEED_SUPPORT == ENABLED)
   #include "cipher/seed.h"
#endif

//ARIA support?
#if (ARIA_SUPPORT == ENABLED)
   #include "cipher/aria.h"
#endif

//PRESENT support?
#if (PRESENT_SUPPORT == ENABLED)
   #include "cipher/present.h"
#endif

//C++ guard
#ifdef __cplusplus
   extern "C" {
#endif


/**
 * @brief CMAC algorithm context
 **/

typedef struct
{
   const CipherAlgo *cipher;
   uint8_t cipherContext[MAX_CIPHER_CONTEXT_SIZE];
   uint8_t k1[MAX_CIPHER_BLOCK_SIZE];
   uint8_t k2[MAX_CIPHER_BLOCK_SIZE];
   uint8_t buffer[MAX_CIPHER_BLOCK_SIZE];
   size_t bufferLength;
   uint8_t mac[MAX_CIPHER_BLOCK_SIZE];
} CmacContext;


//CMAC related functions
error_t cmacCompute(const CipherAlgo *cipher, const void *key, size_t keyLen,
   const void *data, size_t dataLen, uint8_t *mac, size_t macLen);

error_t cmacInit(CmacContext *context, const CipherAlgo *cipher,
   const void *key, size_t keyLen);

void cmacReset(CmacContext *context);
void cmacUpdate(CmacContext *context, const void *data, size_t dataLen);
error_t cmacFinal(CmacContext *context, uint8_t *mac, size_t macLen);

void cmacMul(uint8_t *x, const uint8_t *a, size_t n, uint8_t rb);
void cmacXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n);

//C++ guard
#ifdef __cplusplus
   }
#endif

#endif
