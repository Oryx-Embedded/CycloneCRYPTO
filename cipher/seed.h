/**
 * @file seed.h
 * @brief SEED encryption algorithm
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

#ifndef _SEED_H
#define _SEED_H

//Dependencies
#include "core/crypto.h"

//SEED block size
#define SEED_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define SEED_CIPHER_ALGO (&seedCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SEED algorithm context
 **/

typedef struct
{
   uint32_t ks[32];
} SeedContext;


//SEED related constants
extern const CipherAlgo seedCipherAlgo;

//SEED related functions
error_t seedInit(SeedContext *context, const uint8_t *key, size_t keyLen);

void seedEncryptBlock(SeedContext *context, const uint8_t *input,
   uint8_t *output);

void seedDecryptBlock(SeedContext *context, const uint8_t *input,
   uint8_t *output);

void seedDeinit(SeedContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
