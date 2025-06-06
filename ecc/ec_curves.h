/**
 * @file ec_curves.h
 * @brief Elliptic curves
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

#ifndef _EC_CURVES_H
#define _EC_CURVES_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"

//Elliptic curves
#define SECP112R1_CURVE (&secp112r1Curve)
#define SECP112R2_CURVE (&secp112r2Curve)
#define SECP128R1_CURVE (&secp128r1Curve)
#define SECP128R2_CURVE (&secp128r2Curve)
#define SECP160K1_CURVE (&secp160k1Curve)
#define SECP160R1_CURVE (&secp160r1Curve)
#define SECP160R2_CURVE (&secp160r2Curve)
#define SECP192K1_CURVE (&secp192k1Curve)
#define SECP192R1_CURVE (&secp192r1Curve)
#define SECP224K1_CURVE (&secp224k1Curve)
#define SECP224R1_CURVE (&secp224r1Curve)
#define SECP256K1_CURVE (&secp256k1Curve)
#define SECP256R1_CURVE (&secp256r1Curve)
#define SECP384R1_CURVE (&secp384r1Curve)
#define SECP521R1_CURVE (&secp521r1Curve)
#define BRAINPOOLP160R1_CURVE (&brainpoolP160r1Curve)
#define BRAINPOOLP160T1_CURVE (&brainpoolP160t1Curve)
#define BRAINPOOLP192R1_CURVE (&brainpoolP192r1Curve)
#define BRAINPOOLP192T1_CURVE (&brainpoolP192t1Curve)
#define BRAINPOOLP224R1_CURVE (&brainpoolP224r1Curve)
#define BRAINPOOLP224T1_CURVE (&brainpoolP224t1Curve)
#define BRAINPOOLP256R1_CURVE (&brainpoolP256r1Curve)
#define BRAINPOOLP256T1_CURVE (&brainpoolP256t1Curve)
#define BRAINPOOLP320R1_CURVE (&brainpoolP320r1Curve)
#define BRAINPOOLP320T1_CURVE (&brainpoolP320t1Curve)
#define BRAINPOOLP384R1_CURVE (&brainpoolP384r1Curve)
#define BRAINPOOLP384T1_CURVE (&brainpoolP384t1Curve)
#define BRAINPOOLP512R1_CURVE (&brainpoolP512r1Curve)
#define BRAINPOOLP512T1_CURVE (&brainpoolP512t1Curve)
#define FRP256V1_CURVE (&frp256v1Curve)
#define SM2_CURVE (&sm2Curve)
#define X25519_CURVE (&x25519Curve)
#define X448_CURVE (&x448Curve)
#define ED25519_CURVE (&ed25519Curve)
#define ED448_CURVE (&ed448Curve)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Constants
extern const uint8_t SECP112R1_OID[5];
extern const uint8_t SECP112R2_OID[5];
extern const uint8_t SECP128R1_OID[5];
extern const uint8_t SECP128R2_OID[5];
extern const uint8_t SECP160K1_OID[5];
extern const uint8_t SECP160R1_OID[5];
extern const uint8_t SECP160R2_OID[5];
extern const uint8_t SECP192K1_OID[5];
extern const uint8_t SECP192R1_OID[8];
extern const uint8_t SECP224K1_OID[5];
extern const uint8_t SECP224R1_OID[5];
extern const uint8_t SECP256K1_OID[5];
extern const uint8_t SECP256R1_OID[8];
extern const uint8_t SECP384R1_OID[5];
extern const uint8_t SECP521R1_OID[5];
extern const uint8_t BRAINPOOLP160R1_OID[9];
extern const uint8_t BRAINPOOLP160T1_OID[9];
extern const uint8_t BRAINPOOLP192R1_OID[9];
extern const uint8_t BRAINPOOLP192T1_OID[9];
extern const uint8_t BRAINPOOLP224R1_OID[9];
extern const uint8_t BRAINPOOLP224T1_OID[9];
extern const uint8_t BRAINPOOLP256R1_OID[9];
extern const uint8_t BRAINPOOLP256T1_OID[9];
extern const uint8_t BRAINPOOLP320R1_OID[9];
extern const uint8_t BRAINPOOLP320T1_OID[9];
extern const uint8_t BRAINPOOLP384R1_OID[9];
extern const uint8_t BRAINPOOLP384T1_OID[9];
extern const uint8_t BRAINPOOLP512R1_OID[9];
extern const uint8_t BRAINPOOLP512T1_OID[9];
extern const uint8_t FRP256V1_OID[10];
extern const uint8_t SM2_OID[8];
extern const uint8_t X25519_OID[3];
extern const uint8_t X448_OID[3];
extern const uint8_t ED25519_OID[3];
extern const uint8_t ED448_OID[3];

extern const EcCurve secp112r1Curve;
extern const EcCurve secp112r1Curve;
extern const EcCurve secp112r2Curve;
extern const EcCurve secp128r1Curve;
extern const EcCurve secp128r2Curve;
extern const EcCurve secp160k1Curve;
extern const EcCurve secp160r1Curve;
extern const EcCurve secp160r2Curve;
extern const EcCurve secp192k1Curve;
extern const EcCurve secp192r1Curve;
extern const EcCurve secp224k1Curve;
extern const EcCurve secp224r1Curve;
extern const EcCurve secp256k1Curve;
extern const EcCurve secp256r1Curve;
extern const EcCurve secp384r1Curve;
extern const EcCurve secp521r1Curve;
extern const EcCurve brainpoolP160r1Curve;
extern const EcCurve brainpoolP160t1Curve;
extern const EcCurve brainpoolP192r1Curve;
extern const EcCurve brainpoolP192t1Curve;
extern const EcCurve brainpoolP224r1Curve;
extern const EcCurve brainpoolP224t1Curve;
extern const EcCurve brainpoolP256r1Curve;
extern const EcCurve brainpoolP256t1Curve;
extern const EcCurve brainpoolP320r1Curve;
extern const EcCurve brainpoolP320t1Curve;
extern const EcCurve brainpoolP384r1Curve;
extern const EcCurve brainpoolP384t1Curve;
extern const EcCurve brainpoolP512r1Curve;
extern const EcCurve brainpoolP512t1Curve;
extern const EcCurve frp256v1Curve;
extern const EcCurve sm2Curve;
extern const EcCurve x25519Curve;
extern const EcCurve x448Curve;
extern const EcCurve ed25519Curve;
extern const EcCurve ed448Curve;

//Fast modular reduction
void secp112r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp112r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp112r2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp112r2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp128r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp128r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp128r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp128r2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp128r2FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp128r2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp160k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp160k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp160k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp160r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp160r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp160r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp160r2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp160r2FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp160r2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp192k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp192k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp192k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp192r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp192r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp192r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp224k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp224k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp224k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp224r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp224r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp224r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp256k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp256k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp256k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp256r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp256r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp256r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp256r1ScalarInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp384r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp384r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp384r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp384r1ScalarInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void secp521r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp521r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp521r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void secp521r1ScalarInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP160r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP160r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP160t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP160t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP192r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP192r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP192t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP192t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP224r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP224r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP224t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP224t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP256r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP256r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP256t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP256t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP320r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP320r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP320t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP320t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP384r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP384r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP384t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP384t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP512r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP512r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void brainpoolP512t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void brainpoolP512t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void frp256v1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void frp256v1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

void sm2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void sm2FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a);
void sm2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a);

const EcCurve *ecGetCurve(const uint8_t *oid, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
