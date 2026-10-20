/**
 * @file aegis128l.h
 * @brief AEGIS-128L AEAD
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

#ifndef _AEGIS128L_H
#define _AEGIS128L_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief AEGIS-128L state
 **/

typedef uint32_t Aegis128lState[8][4];


//AEGIS-128L related functions
error_t aegis128lEncrypt(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c,
   size_t length, uint8_t *t, size_t tLen);

error_t aegis128lDecrypt(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p,
   size_t length, const uint8_t *t, size_t tLen);

error_t aegis128lStream(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, uint8_t *ks, size_t ksLen);

void aegis128lUpdate(Aegis128lState s, const uint8_t *m0, const uint8_t *m1);
void aegis128lInit(Aegis128lState s, const uint8_t *key, const uint8_t *nonce);
void aegis128lAbsorb(Aegis128lState s, const uint8_t *ai);
void aegis128lEnc(Aegis128lState s, const uint8_t *xi, uint8_t *ci);
void aegis128lDec(Aegis128lState s, const uint8_t *ci, uint8_t *xi);

void aegis128lDecPartial(Aegis128lState s, const uint8_t *cn, uint8_t *xn,
   size_t length);

void aegis128lFinalize(Aegis128lState s, size_t adLen, size_t msgLen,
   uint8_t *tag, size_t tagLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
