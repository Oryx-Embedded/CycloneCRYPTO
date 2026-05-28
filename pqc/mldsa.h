/**
 * @file mldsa.h
 * @brief ML-DSA (Edwards-Curve Digital Signature Algorithm)
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
 * @version 2.6.4
 **/

#ifndef _MLDSA_H
#define _MLDSA_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"

//ML-DSA-44 security level
#define MLDSA44_SECURITY_LEVEL 2
//ML-DSA-44 seed size
#define MLDSA44_SEED_LEN 32
//ML-DSA-44 private key size
#define MLDSA44_PRIVATE_KEY_LEN 2560
//ML-DSA-44 public key size
#define MLDSA44_PUBLIC_KEY_LEN 1312
//ML-DSA-44 signature size
#define MLDSA44_SIGNATURE_LEN 2420

//ML-DSA-65 security level
#define MLDSA65_SECURITY_LEVEL 3
//ML-DSA-65 seed size
#define MLDSA65_SEED_LEN 32
//ML-DSA-65 private key size
#define MLDSA65_PRIVATE_KEY_LEN 4032
//ML-DSA-65 public key size
#define MLDSA65_PUBLIC_KEY_LEN 1952
//ML-DSA-65 signature size
#define MLDSA65_SIGNATURE_LEN 3309

//ML-DSA-87 security level
#define MLDSA87_SECURITY_LEVEL 5
//ML-DSA-87 seed size
#define MLDSA87_SEED_LEN 32
//ML-DSA-87 private key size
#define MLDSA87_PRIVATE_KEY_LEN 4896
//ML-DSA-87 public key size
#define MLDSA87_PUBLIC_KEY_LEN 2592
//ML-DSA-87 signature size
#define MLDSA87_SIGNATURE_LEN 4627

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ML-DSA public key
 **/

typedef struct
{
   uint_t level; ///<Security level
   uint8_t *pk;  ///<Public key
   size_t pkLen; ///<Length of the public key, in bytes
} MldsaPublicKey;


/**
 * @brief ML-DSA private key
 **/

typedef struct
{
   uint_t level;   ///<Security level
   uint8_t *seed;  ///<Seed
   size_t seedLen; ///<Length of the seed, in bytes
   uint8_t *sk;    ///<Secret key
   size_t skLen;   ///<Length of the secret key, in bytes
} MldsaPrivateKey;

//ML-DSA related constants
extern const uint8_t MLDSA44_OID[9];
extern const uint8_t MLDSA65_OID[9];
extern const uint8_t MLDSA87_OID[9];

//ML-DSA related functions
void mldsaInitPublicKey(MldsaPublicKey *key);
void mldsaFreePublicKey(MldsaPublicKey *key);

void mldsaInitPrivateKey(MldsaPrivateKey *key);
void mldsaFreePrivateKey(MldsaPrivateKey *key);

error_t mldsaImportPublicKey(MldsaPublicKey *key, uint_t level,
   const uint8_t *input, size_t length);

error_t mldsaExportPublicKey(const MldsaPublicKey *key, uint8_t *output,
   size_t *written);

error_t mldsaImportPrivateKey(MldsaPrivateKey *key, uint_t level,
   const uint8_t *input, size_t length);

error_t mldsaExportPrivateKey(const MldsaPrivateKey *key, uint8_t *output,
   size_t *written);

error_t mldsaImportSeed(MldsaPrivateKey *key, uint_t level,
   const uint8_t *input, size_t length);

error_t mldsaExportSeed(const MldsaPrivateKey *key, uint8_t *output,
   size_t *written);

error_t mldsa44GenerateSignature(const uint8_t *secretKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   uint8_t *signature);

error_t mldsa65GenerateSignature(const uint8_t *secretKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   uint8_t *signature);

error_t mldsa87GenerateSignature(const uint8_t *secretKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   uint8_t *signature);

error_t mldsa44VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   const uint8_t *signature);

error_t mldsa65VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   const uint8_t *signature);

error_t mldsa87VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   const uint8_t *signature);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
