/**
 * @file ec_misc.h
 * @brief Helper routines for ECC
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

#ifndef _EC_MISC_H
#define _EC_MISC_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Scalar import/export format
 **/

typedef enum
{
   EC_SCALAR_FORMAT_LITTLE_ENDIAN = 0,
   EC_SCALAR_FORMAT_BIG_ENDIAN    = 1
} EcScalarFormat;


//EC related functions
error_t ecScalarImport(uint32_t *r, uint_t n, const uint8_t *input,
   size_t length, EcScalarFormat format);

error_t ecScalarExport(const uint32_t *a, uint_t n, uint8_t *output,
   size_t length, EcScalarFormat format);

uint_t ecScalarGetByteLength(const uint32_t *a, uint_t n);
uint_t ecScalarGetBitLength(const uint32_t *a, uint_t n);

uint32_t ecScalarGetBitValue(const uint32_t *a, int_t index);

int_t ecScalarComp(const uint32_t *a, const uint32_t *b, uint_t n);
int_t ecScalarCompInt(const uint32_t *a, uint32_t b, uint_t n);

uint32_t ecScalarTestEqual(const uint32_t *a, const uint32_t *b, uint_t n);
uint32_t ecScalarTestEqualInt(const uint32_t *a, uint32_t b, uint_t n);

uint32_t ecScalarTestNotEqual(const uint32_t *a, const uint32_t *b, uint_t n);
uint32_t ecScalarTestNotEqualInt(const uint32_t *a, uint32_t b, uint_t n);

void ecScalarSetInt(uint32_t *a, uint32_t b, uint_t n);

void ecScalarCopy(uint32_t *a, const uint32_t *b, uint_t n);
void ecScalarSwap(uint32_t *a, uint32_t *b, uint32_t c, uint_t n);

void ecScalarSelect(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c, uint_t n);

error_t ecScalarRand(const EcCurve *curve, uint32_t *r,
   const PrngAlgo *prngAlgo, void *prngContext);

uint32_t ecScalarAdd(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint_t n);

uint32_t ecScalarAddInt(uint32_t *r, const uint32_t *a, uint32_t b, uint_t n);

uint32_t ecScalarSub(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint_t n);

uint32_t ecScalarSubInt(uint32_t *r, const uint32_t *a, uint32_t b, uint_t n);

void ecScalarMul(uint32_t *rl, uint32_t *rh, const uint32_t *a,
   const uint32_t *b, uint_t n);

void ecScalarSqr(uint32_t *r, const uint32_t *a, uint_t n);

void ecScalarShiftLeft(uint32_t *r, const uint32_t *a, uint_t k, uint_t n);
void ecScalarShiftRight(uint32_t *r, const uint32_t *a, uint_t k, uint_t n);

void ecScalarMod(uint32_t *r, const uint32_t *a, uint_t m, const uint32_t *p,
   uint_t n);

void ecScalarAddMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b);

void ecScalarSubMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b);

void ecScalarMulMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b);

void ecScalarSqrMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void ecScalarPwr2Mod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   uint_t n);

void ecScalarInvMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void ecFieldAddMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b);

void ecFieldSubMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b);

void ecFieldMulMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b);

void ecFieldSqrMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void ecFieldPwr2Mod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   uint_t n);

void ecFieldInvMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void ecFieldCanonicalize(const EcCurve *curve, uint32_t *r, const uint32_t *a);

uint_t ecTwinMulF(uint_t t);

void ecZaddu(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p,
   const EcPoint3 *q);

void ecZaddc(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p,
   const EcPoint3 *q);

void ecDblu(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p);
void ecTplu(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p);

void ecScalarDump(FILE *stream, const char_t *prepend, const uint32_t *a,
   uint_t n);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
