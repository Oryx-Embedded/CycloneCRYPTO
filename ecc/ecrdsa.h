/**
 * @file ecrdsa.h
 * @brief ECRDSA (Elliptic Curve Russian Digital Signature Algorithm)
 *
 * Elliptic Curve (Russian) Digital Signature Algorithm for Cryptographic API
 *
 * Copyright (c) 2024 Valery Novikov <novikov.val@gmail.com>
 *
 * References:
 * GOST 34.10-2018, GOST R 34.10-2012, RFC 7091, ISO/IEC 14888-3:2018.
 *
 * Historical references:
 * GOST R 34.10-2001, RFC 4357, ISO/IEC 14888-3:2006/Amd 1:2010.
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
 * @author Valery Novikov <novikov.val@gmail.com>
 * @version 2.4.0
 **/

#ifndef _ECRDSA_H
#define _ECRDSA_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ECRDSA signature
 **/

typedef struct
{
   Mpi r;
   Mpi s;
} EcrdsaSignature;


//ECRDSA related constants
extern const uint8_t ECDSA_WITH_SHA1_OID[7];
extern const uint8_t ECDSA_WITH_SHA224_OID[8];
extern const uint8_t ECDSA_WITH_SHA256_OID[8];
extern const uint8_t ECDSA_WITH_SHA384_OID[8];
extern const uint8_t ECDSA_WITH_SHA512_OID[8];
extern const uint8_t ECDSA_WITH_SHA3_224_OID[9];
extern const uint8_t ECDSA_WITH_SHA3_256_OID[9];
extern const uint8_t ECDSA_WITH_SHA3_384_OID[9];
extern const uint8_t ECDSA_WITH_SHA3_512_OID[9];

//ECRDSA related functions
void ecrdsaInitSignature(EcrdsaSignature *signature);
void ecrdsaFreeSignature(EcrdsaSignature *signature);

error_t ecrdsaWriteSignature(const EcrdsaSignature *signature, uint8_t *data,
   size_t *length);

error_t ecrdsaReadSignature(const uint8_t *data, size_t length, EcrdsaSignature *signature);

error_t ecrdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext, 
   const EcDomainParameters *params, const EcPrivateKey *privateKey,
   const uint8_t *digest, size_t digestLen, EcrdsaSignature *signature);

error_t ecrdsaVerifySignature(const EcDomainParameters *params,
   const EcPublicKey *publicKey, const uint8_t *digest, size_t digestLen,
   const EcrdsaSignature *signature);

#if (ECRDSA_TEST_SUPPORT == ENABLED)
error_t ecrdsaTest(void);
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
