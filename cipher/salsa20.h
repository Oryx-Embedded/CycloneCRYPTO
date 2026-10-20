/**
 * @file salsa20.h
 * @brief Salsa20 encryption algorithm
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

#ifndef _SALSA20_H
#define _SALSA20_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Salsa20 algorithm context
 **/

typedef struct
{
   uint_t nr;
   uint32_t state[16];
   uint8_t keystream[64];
   uint_t pos;
} Salsa20Context;


//Salsa20 related functions
error_t salsa20Init(Salsa20Context *context, uint_t nr, const uint8_t *key,
   size_t keyLen, const uint8_t *nonce, size_t nonceLen);

void salsa20Cipher(Salsa20Context *context, const uint8_t *input,
   uint8_t *output, size_t length);

void salsa20ProcessBlock(const uint8_t *input, uint8_t *output, uint_t nr);

void salsa20Deinit(Salsa20Context *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
