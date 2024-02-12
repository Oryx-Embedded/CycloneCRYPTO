/**
 * @file sm2.h
 * @brief SM2 signature algorithm
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
 * @version 2.4.0
 **/

#ifndef _SM2_H
#define _SM2_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ecdsa.h"

//SM2 identifiers
#define SM2_DEFAULT_ID "1234567812345678"
#define SM2_TLS13_ID "TLSv1.3+GM+Cipher+Suite"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SM2 related constants
extern const uint8_t SM2_WITH_SM3_OID[8];

//SM2 related functions
error_t sm2GenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, const EcPrivateKey *privateKey,
   const HashAlgo *hashAlgo, const char_t *id, size_t idLen,
   const void *message, size_t messageLen, EcdsaSignature *signature);

error_t sm2VerifySignature(const EcDomainParameters *params,
   const EcPublicKey *publicKey, const HashAlgo *hashAlgo,
   const char_t *id, size_t idLen, const void *message, size_t messageLen,
   const EcdsaSignature *signature);

error_t sm2ComputeZa(const HashAlgo *hashAlgo, HashContext *hashContext,
   const EcDomainParameters *params, const EcPublicKey *pa, const char_t *ida,
   size_t idaLen, uint8_t *za);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
