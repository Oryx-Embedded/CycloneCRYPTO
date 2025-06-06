/**
 * @file ed448.h
 * @brief Ed448 elliptic curve (constant-time implementation)
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

#ifndef _ED448_H
#define _ED448_H

//Dependencies
#include "core/crypto.h"
#include "ecc/eddsa.h"
#include "xof/shake.h"

//Length of Ed448 private keys
#define ED448_PRIVATE_KEY_LEN 57
//Length of Ed448 public keys
#define ED448_PUBLIC_KEY_LEN 57
//Length of Ed448 signatures
#define ED448_SIGNATURE_LEN 114

//Ed448ph flag
#define ED448_PH_FLAG 1
//Prehash function output size
#define ED448_PH_SIZE 64

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Projective point representation
 **/

typedef struct
{
   int32_t x[16];
   int32_t y[16];
   int32_t z[16];
} Ed448Point;


/**
 * @brief Working state (scalar multiplication)
 **/

typedef struct
{
   Ed448Point u;
   Ed448Point v;
   int32_t a[16];
   int32_t b[16];
   int32_t c[16];
   int32_t d[16];
   int32_t e[16];
   int32_t f[16];
   int32_t g[16];
} Ed448SubState;


/**
 * @brief Working state (public key generation)
 **/

typedef struct
{
   ShakeContext shakeContext;
   Ed448Point a;
   Ed448SubState subState;
} Ed448GeneratePublicKeyState;


/**
 * @brief Working state (signature generation)
 **/

typedef struct
{
   ShakeContext shakeContext;
   uint8_t k[114];
   uint8_t p[57];
   uint8_t r[57];
   uint8_t s[57];
   uint8_t t[57];
   Ed448Point a;
   Ed448SubState subState;
} Ed448GenerateSignatureState;


/**
 * @brief Working state (signature verification)
 **/

typedef struct
{
   ShakeContext shakeContext;
   uint8_t k[114];
   uint8_t p[57];
   uint8_t r[57];
   uint8_t s[57];
   Ed448Point a;
   Ed448SubState subState;
} Ed448VerifySignatureState;


//Ed448 related functions
error_t ed448GenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey, uint8_t *publicKey);

error_t ed448GeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey);

error_t ed448GeneratePublicKey(const uint8_t *privateKey, uint8_t *publicKey);

error_t ed448GenerateSignature(const uint8_t *privateKey,
   const uint8_t *publicKey, const void *message, size_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature);

error_t ed448GenerateSignatureEx(const uint8_t *privateKey,
   const uint8_t *publicKey, const DataChunk *message, uint_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature);

error_t ed448VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen, uint8_t flag,
   const uint8_t *signature);

error_t ed448VerifySignatureEx(const uint8_t *publicKey,
   const DataChunk *message, uint_t messageLen, const void *context,
   uint8_t contextLen, uint8_t flag, const uint8_t *signature);

void ed448Mul(Ed448SubState *state, Ed448Point *r, const uint8_t *k,
   const Ed448Point *p);

void ed448TwinMul(Ed448SubState *state, Ed448Point *r, const uint8_t *k1,
   const Ed448Point *p, const uint8_t *k2, const Ed448Point *q);

void ed448Add(Ed448SubState *state, Ed448Point *r, const Ed448Point *p,
   const Ed448Point *q);

void ed448Double(Ed448SubState *state, Ed448Point *r, const Ed448Point *p);

void ed448Encode(Ed448Point *p, uint8_t *data);
uint32_t ed448Decode(Ed448Point *p, const uint8_t *data);

void ed448RedInt(uint8_t *r, const uint8_t *a);

void ed448AddInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n);
uint8_t ed448SubInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n);

void ed448MulInt(uint8_t *rl, uint8_t *rh, const uint8_t *a,
   const uint8_t *b, uint_t n);

void ed448CopyInt(uint8_t *a, const uint8_t *b, uint_t n);

void ed448SelectInt(uint8_t *r, const uint8_t *a, const uint8_t *b,
   uint8_t c, uint_t n);

uint8_t ed448CompInt(const uint8_t *a, const uint8_t *b, uint_t n);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
