/**
 * @file curve448.h
 * @brief Curve448 elliptic curve (constant-time implementation)
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

#ifndef _CURVE448_H
#define _CURVE448_H

//Dependencies
#include "core/crypto.h"

//Speed optimization level
#ifndef CURVE448_SPEED_OPTIMIZATION_LEVEL
   #define CURVE448_SPEED_OPTIMIZATION_LEVEL 2
#elif (CURVE448_SPEED_OPTIMIZATION_LEVEL < 0)
   #error CURVE448_SPEED_OPTIMIZATION_LEVEL parameter is not valid
#endif

//Length of the elliptic curve
#define CURVE448_BIT_LEN 448
#define CURVE448_BYTE_LEN 56
#define CURVE448_WORD_LEN 14

//A24 constant
#define CURVE448_A24 39082

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Curve448 related functions
void curve448SetInt(int32_t *a, int32_t b);

void curve448Add(int32_t *r, const int32_t *a, const int32_t *b);
void curve448AddInt(int32_t *r, const int32_t *a, int32_t b);

void curve448Sub(int32_t *r, const int32_t *a, const int32_t *b);
void curve448SubInt(int32_t *r, const int32_t *a, int32_t b);

void curve448Mul(int32_t *r, const int32_t *a, const int32_t *b);
void curve448MulInt(int32_t *r, const int32_t *a, int32_t b);
void curve448Sqr(int32_t *r, const int32_t *a);
void curve448Pwr2(int32_t *r, const int32_t *a, uint_t n);

void curve448Inv(int32_t *r, const int32_t *a);

uint32_t curve448Sqrt(int32_t *r, const int32_t *a, const int32_t *b);

void curve448Canonicalize(int32_t *r, const int32_t *a);

void curve448Copy(int32_t *a, const int32_t *b);
void curve448Swap(int32_t *a, int32_t *b, uint32_t c);

void curve448Select(int32_t *r, const int32_t *a, const int32_t *b,
   uint32_t c);

uint32_t curve448Comp(const int32_t *a, const int32_t *b);

void curve448Import(int32_t *a, const uint8_t *data);
void curve448Export(int32_t *a, uint8_t *data);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
