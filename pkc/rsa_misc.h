/**
 * @file rsa_misc.h
 * @brief Helper routines for RSA
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

#ifndef _RSA_MISC_H
#define _RSA_MISC_H

//Dependencies
#include "core/crypto.h"
#include "pkc/rsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//RSA related functions
error_t rsaep(const RsaPublicKey *key, const Mpi *m, Mpi *c);
error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m);

error_t rsasp1(const RsaPrivateKey *key, const Mpi *m, Mpi *s);
error_t rsavp1(const RsaPublicKey *key, const Mpi *s, Mpi *m);

error_t emePkcs1v15Encode(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *message, size_t messageLen, uint8_t *em, size_t k);

uint32_t emePkcs1v15Decode(uint8_t *em, size_t k, size_t *messageLen);

error_t emeOaepEncode(const PrngAlgo *prngAlgo, void *prngContext,
   const HashAlgo *hash, const char_t *label, const uint8_t *message,
   size_t messageLen, uint8_t *em, size_t k);

uint32_t emeOaepDecode(const HashAlgo *hash, const char_t *label, uint8_t *em,
   size_t k, size_t *messageLen);

error_t emsaPkcs1v15Encode(const HashAlgo *hash,
   const uint8_t *digest, uint8_t *em, size_t emLen);

error_t emsaPkcs1v15Verify(const HashAlgo *hash, const uint8_t *digest,
   const uint8_t *em, size_t emLen);

error_t emsaPssEncode(const PrngAlgo *prngAlgo, void *prngContext,
   const HashAlgo *hash, size_t saltLen, const uint8_t *digest,
   uint8_t *em, uint_t emBits);

error_t emsaPssVerify(const HashAlgo *hash, size_t saltLen,
   const uint8_t *digest, uint8_t *em, uint_t emBits);

void mgf1(const HashAlgo *hash, HashContext *hashContext, const uint8_t *seed,
   size_t seedLen, uint8_t *data, size_t dataLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
