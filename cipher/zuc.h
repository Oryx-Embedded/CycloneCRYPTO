/**
 * @file zuc.h
 * @brief ZUC stream cipher (ZUC-128 and ZUC-256)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.2
 **/

#ifndef _ZUC_H
#define _ZUC_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ZUC algorithm context
 **/

typedef struct
{
   uint32_t r1;
   uint32_t r2;
   uint32_t s[16];
   uint32_t ks;
   size_t n;
} ZucContext;


//ZUC related functions
error_t zucInit(ZucContext *context, const uint8_t *key, size_t keyLen,
   const uint8_t *iv, size_t ivLen);

void zucGenerateKeyStream(ZucContext *context, uint32_t *output,
   size_t length);

void zucCipher(ZucContext *context, const uint8_t *input, uint8_t *output,
   size_t length);

void zucDeinit(ZucContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
