/**
 * @file aegis256.h
 * @brief AEGIS-256 AEAD
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

#ifndef _AEGIS256_H
#define _AEGIS256_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief AEGIS-256 state
 **/

typedef uint32_t Aegis256State[6][4];


//AEGIS-256 related functions
error_t aegis256Encrypt(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c,
   size_t length, uint8_t *t, size_t tLen);

error_t aegis256Decrypt(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p,
   size_t length, const uint8_t *t, size_t tLen);

error_t aegis256Stream(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, uint8_t *ks, size_t ksLen);

void aegis256Update(Aegis256State s, const uint8_t *m);
void aegis256Init(Aegis256State s, const uint8_t *key, const uint8_t *nonce);
void aegis256Absorb(Aegis256State s, const uint8_t *ai);
void aegis256Enc(Aegis256State s, const uint8_t *xi, uint8_t *ci);
void aegis256Dec(Aegis256State s, const uint8_t *ci, uint8_t *xi);

void aegis256DecPartial(Aegis256State s, const uint8_t *cn, uint8_t *xn,
   size_t length);

void aegis256Finalize(Aegis256State s, size_t adLen, size_t msgLen,
   uint8_t *tag, size_t tagLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
