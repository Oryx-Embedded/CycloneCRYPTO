/**
 * @file tea.h
 * @brief TEA (Tiny Encryption Algorithm)
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

#ifndef _TEA_H
#define _TEA_H

//Dependencies
#include "core/crypto.h"

//Application specific context
#ifndef TEA_PRIVATE_CONTEXT
   #define TEA_PRIVATE_CONTEXT
#endif

//TEA block size
#define TEA_BLOCK_SIZE 8
//TEA number of rounds
#define TEA_NB_ROUNDS 32
//Common interface for encryption algorithms
#define TEA_CIPHER_ALGO (&teaCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief TEA algorithm context
 **/

typedef struct
{
   uint32_t k[4];
   TEA_PRIVATE_CONTEXT
} TeaContext;


//TEA related constants
extern const CipherAlgo teaCipherAlgo;

//TEA related functions
error_t teaInit(TeaContext *context, const uint8_t *key, size_t keyLen);

void teaEncryptBlock(TeaContext *context, const uint8_t *input,
   uint8_t *output);

void teaDecryptBlock(TeaContext *context, const uint8_t *input,
   uint8_t *output);

void teaDeinit(TeaContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
