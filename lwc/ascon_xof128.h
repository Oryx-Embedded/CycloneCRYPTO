/**
 * @file ascon_xof128.h
 * @brief Ascon-XOF128 extendable-output function
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

#ifndef _ASCON_XOF128_H
#define _ASCON_XOF128_H

//Dependencies
#include "core/crypto.h"
#include "lwc/ascon.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Ascon-XOF128 algorithm context
 **/

typedef struct
{
   AsconState state;
   uint8_t buffer[8];
   size_t length;
} AsconXof128Context;

//Ascon-XOF128 related functions
error_t asconXof128Compute(const void *input, size_t inputLen, uint8_t *output,
   size_t outputLen);

void asconXof128Init(AsconXof128Context *context);

void asconXof128Absorb(AsconXof128Context *context, const void *input,
   size_t length);

void asconXof128Final(AsconXof128Context *context);

void asconXof128Squeeze(AsconXof128Context *context, uint8_t *output,
   size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
