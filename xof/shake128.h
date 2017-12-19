/**
 * @file shake128.h
 * @brief SHAKE128 extendable-output function (XOF)
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

#ifndef _SHAKE128_H
#define _SHAKE128_H

//Dependencies
#include "core/crypto.h"
#include "xof/keccak.h"

//C++ guard
#ifdef __cplusplus
   extern "C" {
#endif


/**
 * @brief SHAKE128 algorithm context
 **/

typedef KeccakContext Shake128Context;


//SHAKE128 related constants
extern const uint8_t shake128Oid[9];

//SHAKE128 related functions
error_t shake128Compute(const void *input, size_t inputLen,
   uint8_t *output, size_t outputLen);

void shake128Init(Shake128Context *context);
void shake128Absorb(Shake128Context *context, const void *input, size_t length);
void shake128Final(Shake128Context *context);
void shake128Squeeze(Shake128Context *context, uint8_t *output, size_t length);

//C++ guard
#ifdef __cplusplus
   }
#endif

#endif
