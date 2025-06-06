/**
 * @file curve25519.h
 * @brief Curve25519 elliptic curve (constant-time implementation)
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

#ifndef _CURVE25519_H
#define _CURVE25519_H

//Dependencies
#include "core/crypto.h"

//Speed optimization level
#ifndef CURVE25519_SPEED_OPTIMIZATION_LEVEL
   #define CURVE25519_SPEED_OPTIMIZATION_LEVEL 2
#elif (CURVE25519_SPEED_OPTIMIZATION_LEVEL < 0)
   #error CURVE25519_SPEED_OPTIMIZATION_LEVEL parameter is not valid
#endif

//Length of the elliptic curve
#define CURVE25519_BIT_LEN 255
#define CURVE25519_BYTE_LEN 32
#define CURVE25519_WORD_LEN 8

//A24 constant
#define CURVE25519_A24 121666

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Curve25519 related functions
void curve25519SetInt(int32_t *a, int32_t b);

void curve25519Add(int32_t *r, const int32_t *a, const int32_t *b);
void curve25519AddInt(int32_t *r, const int32_t *a, int32_t b);

void curve25519Sub(int32_t *r, const int32_t *a, const int32_t *b);
void curve25519SubInt(int32_t *r, const int32_t *a, int32_t b);

void curve25519Mul(int32_t *r, const int32_t *a, const int32_t *b);
void curve25519MulInt(int32_t *r, const int32_t *a, int32_t b);
void curve25519Sqr(int32_t *r, const int32_t *a);
void curve25519Pwr2(int32_t *r, const int32_t *a, uint_t n);

void curve25519Inv(int32_t *r, const int32_t *a);

uint32_t curve25519Sqrt(int32_t *r, const int32_t *a, const int32_t *b);

void curve25519Canonicalize(int32_t *r, const int32_t *a);

void curve25519Copy(int32_t *a, const int32_t *b);
void curve25519Swap(int32_t *a, int32_t *b, uint32_t c);

void curve25519Select(int32_t *r, const int32_t *a, const int32_t *b,
   uint32_t c);

uint32_t curve25519Comp(const int32_t *a, const int32_t *b);

void curve25519Import(int32_t *a, const uint8_t *data);
void curve25519Export(int32_t *a, uint8_t *data);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
