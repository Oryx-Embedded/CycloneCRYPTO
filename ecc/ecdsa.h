/**
 * @file ecdsa.h
 * @brief ECDSA (Elliptic Curve Digital Signature Algorithm)
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

#ifndef _ECDSA_H
#define _ECDSA_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"
#include "ecc/ec_curves.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ECDSA signature format
 **/

typedef enum
{
   ECDSA_SIGNATURE_FORMAT_ASN1  = 0,
   ECDSA_SIGNATURE_FORMAT_RAW   = 1,
   ECDSA_SIGNATURE_FORMAT_RAW_R = 2,
   ECDSA_SIGNATURE_FORMAT_RAW_S = 3
} EcdsaSignatureFormat;


/**
 * @brief ECDSA signature
 **/

typedef struct
{
   const EcCurve *curve;          ///<Elliptic curve parameters
   uint32_t r[EC_MAX_ORDER_SIZE]; ///<Integer R
   uint32_t s[EC_MAX_ORDER_SIZE]; ///<Integer S
} EcdsaSignature;


/**
 * @brief Working state (ECDSA signature generation)
 **/

typedef struct
{
   uint32_t k[EC_MAX_ORDER_SIZE];
   uint32_t z[EC_MAX_ORDER_SIZE];
   EcPoint3 r1;
} EcdsaGenerateSignatureState;


/**
 * @brief Working state (ECDSA signature verification)
 **/

typedef struct
{
   uint32_t w[EC_MAX_ORDER_SIZE];
   uint32_t z[EC_MAX_ORDER_SIZE];
   uint32_t u1[EC_MAX_ORDER_SIZE];
   uint32_t u2[EC_MAX_ORDER_SIZE];
   uint32_t v[EC_MAX_ORDER_SIZE];
   EcPoint3 v0;
   EcPoint3 v1;
} EcdsaVerifySignatureState;


//ECDSA related constants
extern const uint8_t ECDSA_WITH_SHA1_OID[7];
extern const uint8_t ECDSA_WITH_SHA224_OID[8];
extern const uint8_t ECDSA_WITH_SHA256_OID[8];
extern const uint8_t ECDSA_WITH_SHA384_OID[8];
extern const uint8_t ECDSA_WITH_SHA512_OID[8];
extern const uint8_t ECDSA_WITH_SHA3_224_OID[9];
extern const uint8_t ECDSA_WITH_SHA3_256_OID[9];
extern const uint8_t ECDSA_WITH_SHA3_384_OID[9];
extern const uint8_t ECDSA_WITH_SHA3_512_OID[9];
extern const uint8_t ECDSA_WITH_SHAKE128_OID[8];
extern const uint8_t ECDSA_WITH_SHAKE256_OID[8];

//ECDSA related functions
void ecdsaInitSignature(EcdsaSignature *signature);
void ecdsaFreeSignature(EcdsaSignature *signature);

error_t ecdsaImportSignature(EcdsaSignature *signature, const EcCurve *curve,
   const uint8_t *input, size_t length, EcdsaSignatureFormat format);

error_t ecdsaExportSignature(const EcdsaSignature *signature, uint8_t *output,
   size_t *written, EcdsaSignatureFormat format);

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcPrivateKey *privateKey, const uint8_t *digest, size_t digestLen,
   EcdsaSignature *signature);

error_t ecdsaVerifySignature(const EcPublicKey *publicKey,
   const uint8_t *digest, size_t digestLen, const EcdsaSignature *signature);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
