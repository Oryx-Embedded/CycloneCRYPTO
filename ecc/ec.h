/**
 * @file ec.h
 * @brief ECC (Elliptic Curve Cryptography)
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

#ifndef _EC_H
#define _EC_H

//Dependencies
#include "core/crypto.h"

//secp112r1 elliptic curve support
#ifndef SECP112R1_SUPPORT
   #define SECP112R1_SUPPORT DISABLED
#elif (SECP112R1_SUPPORT != ENABLED && SECP112R1_SUPPORT != DISABLED)
   #error SECP112R1_SUPPORT parameter is not valid
#endif

//secp112r2 elliptic curve support
#ifndef SECP112R2_SUPPORT
   #define SECP112R2_SUPPORT DISABLED
#elif (SECP112R2_SUPPORT != ENABLED && SECP112R2_SUPPORT != DISABLED)
   #error SECP112R2_SUPPORT parameter is not valid
#endif

//secp128r1 elliptic curve support
#ifndef SECP128R1_SUPPORT
   #define SECP128R1_SUPPORT DISABLED
#elif (SECP128R1_SUPPORT != ENABLED && SECP128R1_SUPPORT != DISABLED)
   #error SECP128R1_SUPPORT parameter is not valid
#endif

//secp128r2 elliptic curve support
#ifndef SECP128R2_SUPPORT
   #define SECP128R2_SUPPORT DISABLED
#elif (SECP128R2_SUPPORT != ENABLED && SECP128R2_SUPPORT != DISABLED)
   #error SECP128R2_SUPPORT parameter is not valid
#endif

//secp160k1 elliptic curve support
#ifndef SECP160K1_SUPPORT
   #define SECP160K1_SUPPORT DISABLED
#elif (SECP160K1_SUPPORT != ENABLED && SECP160K1_SUPPORT != DISABLED)
   #error SECP160K1_SUPPORT parameter is not valid
#endif

//secp160r1 elliptic curve support
#ifndef SECP160R1_SUPPORT
   #define SECP160R1_SUPPORT DISABLED
#elif (SECP160R1_SUPPORT != ENABLED && SECP160R1_SUPPORT != DISABLED)
   #error SECP160R1_SUPPORT parameter is not valid
#endif

//secp160r2 elliptic curve support
#ifndef SECP160R2_SUPPORT
   #define SECP160R2_SUPPORT DISABLED
#elif (SECP160R2_SUPPORT != ENABLED && SECP160R2_SUPPORT != DISABLED)
   #error SECP160R2_SUPPORT parameter is not valid
#endif

//secp192k1 elliptic curve support
#ifndef SECP192K1_SUPPORT
   #define SECP192K1_SUPPORT DISABLED
#elif (SECP192K1_SUPPORT != ENABLED && SECP192K1_SUPPORT != DISABLED)
   #error SECP192K1_SUPPORT parameter is not valid
#endif

//secp192r1 elliptic curve support (NIST P-192)
#ifndef SECP192R1_SUPPORT
   #define SECP192R1_SUPPORT DISABLED
#elif (SECP192R1_SUPPORT != ENABLED && SECP192R1_SUPPORT != DISABLED)
   #error SECP192R1_SUPPORT parameter is not valid
#endif

//secp224k1 elliptic curve support
#ifndef SECP224K1_SUPPORT
   #define SECP224K1_SUPPORT DISABLED
#elif (SECP224K1_SUPPORT != ENABLED && SECP224K1_SUPPORT != DISABLED)
   #error SECP224K1_SUPPORT parameter is not valid
#endif

//secp224r1 elliptic curve support (NIST P-224)
#ifndef SECP224R1_SUPPORT
   #define SECP224R1_SUPPORT ENABLED
#elif (SECP224R1_SUPPORT != ENABLED && SECP224R1_SUPPORT != DISABLED)
   #error SECP224R1_SUPPORT parameter is not valid
#endif

//secp256k1 elliptic curve support
#ifndef SECP256K1_SUPPORT
   #define SECP256K1_SUPPORT DISABLED
#elif (SECP256K1_SUPPORT != ENABLED && SECP256K1_SUPPORT != DISABLED)
   #error SECP256K1_SUPPORT parameter is not valid
#endif

//secp256r1 elliptic curve support (NIST P-256)
#ifndef SECP256R1_SUPPORT
   #define SECP256R1_SUPPORT ENABLED
#elif (SECP256R1_SUPPORT != ENABLED && SECP256R1_SUPPORT != DISABLED)
   #error SECP256R1_SUPPORT parameter is not valid
#endif

//secp384r1 elliptic curve support (NIST P-384)
#ifndef SECP384R1_SUPPORT
   #define SECP384R1_SUPPORT ENABLED
#elif (SECP384R1_SUPPORT != ENABLED && SECP384R1_SUPPORT != DISABLED)
   #error SECP384R1_SUPPORT parameter is not valid
#endif

//secp521r1 elliptic curve support (NIST P-521)
#ifndef SECP521R1_SUPPORT
   #define SECP521R1_SUPPORT ENABLED
#elif (SECP521R1_SUPPORT != ENABLED && SECP521R1_SUPPORT != DISABLED)
   #error SECP521R1_SUPPORT parameter is not valid
#endif

//brainpoolP160r1 elliptic curve support
#ifndef BRAINPOOLP160R1_SUPPORT
   #define BRAINPOOLP160R1_SUPPORT DISABLED
#elif (BRAINPOOLP160R1_SUPPORT != ENABLED && BRAINPOOLP160R1_SUPPORT != DISABLED)
   #error BRAINPOOLP160R1_SUPPORT parameter is not valid
#endif

//brainpoolP160t1 elliptic curve support
#ifndef BRAINPOOLP160T1_SUPPORT
   #define BRAINPOOLP160T1_SUPPORT DISABLED
#elif (BRAINPOOLP160T1_SUPPORT != ENABLED && BRAINPOOLP160T1_SUPPORT != DISABLED)
   #error BRAINPOOLP160T1_SUPPORT parameter is not valid
#endif

//brainpoolP192r1 elliptic curve support
#ifndef BRAINPOOLP192R1_SUPPORT
   #define BRAINPOOLP192R1_SUPPORT DISABLED
#elif (BRAINPOOLP192R1_SUPPORT != ENABLED && BRAINPOOLP192R1_SUPPORT != DISABLED)
   #error BRAINPOOLP192R1_SUPPORT parameter is not valid
#endif

//brainpoolP192t1 elliptic curve support
#ifndef BRAINPOOLP192T1_SUPPORT
   #define BRAINPOOLP192T1_SUPPORT DISABLED
#elif (BRAINPOOLP192T1_SUPPORT != ENABLED && BRAINPOOLP192T1_SUPPORT != DISABLED)
   #error BRAINPOOLP192T1_SUPPORT parameter is not valid
#endif

//brainpoolP224r1 elliptic curve support
#ifndef BRAINPOOLP224R1_SUPPORT
   #define BRAINPOOLP224R1_SUPPORT DISABLED
#elif (BRAINPOOLP224R1_SUPPORT != ENABLED && BRAINPOOLP224R1_SUPPORT != DISABLED)
   #error BRAINPOOLP224R1_SUPPORT parameter is not valid
#endif

//brainpoolP224t1 elliptic curve support
#ifndef BRAINPOOLP224T1_SUPPORT
   #define BRAINPOOLP224T1_SUPPORT DISABLED
#elif (BRAINPOOLP224T1_SUPPORT != ENABLED && BRAINPOOLP224T1_SUPPORT != DISABLED)
   #error BRAINPOOLP224T1_SUPPORT parameter is not valid
#endif

//brainpoolP256r1 elliptic curve support
#ifndef BRAINPOOLP256R1_SUPPORT
   #define BRAINPOOLP256R1_SUPPORT DISABLED
#elif (BRAINPOOLP256R1_SUPPORT != ENABLED && BRAINPOOLP256R1_SUPPORT != DISABLED)
   #error BRAINPOOLP256R1_SUPPORT parameter is not valid
#endif

//brainpoolP256t1 elliptic curve support
#ifndef BRAINPOOLP256T1_SUPPORT
   #define BRAINPOOLP256T1_SUPPORT DISABLED
#elif (BRAINPOOLP256T1_SUPPORT != ENABLED && BRAINPOOLP256T1_SUPPORT != DISABLED)
   #error BRAINPOOLP256T1_SUPPORT parameter is not valid
#endif

//brainpoolP320r1 elliptic curve support
#ifndef BRAINPOOLP320R1_SUPPORT
   #define BRAINPOOLP320R1_SUPPORT DISABLED
#elif (BRAINPOOLP320R1_SUPPORT != ENABLED && BRAINPOOLP320R1_SUPPORT != DISABLED)
   #error BRAINPOOLP320R1_SUPPORT parameter is not valid
#endif

//brainpoolP320t1 elliptic curve support
#ifndef BRAINPOOLP320T1_SUPPORT
   #define BRAINPOOLP320T1_SUPPORT DISABLED
#elif (BRAINPOOLP320T1_SUPPORT != ENABLED && BRAINPOOLP320T1_SUPPORT != DISABLED)
   #error BRAINPOOLP320T1_SUPPORT parameter is not valid
#endif

//brainpoolP384r1 elliptic curve support
#ifndef BRAINPOOLP384R1_SUPPORT
   #define BRAINPOOLP384R1_SUPPORT DISABLED
#elif (BRAINPOOLP384R1_SUPPORT != ENABLED && BRAINPOOLP384R1_SUPPORT != DISABLED)
   #error BRAINPOOLP384R1_SUPPORT parameter is not valid
#endif

//brainpoolP384t1 elliptic curve support
#ifndef BRAINPOOLP384T1_SUPPORT
   #define BRAINPOOLP384T1_SUPPORT DISABLED
#elif (BRAINPOOLP384T1_SUPPORT != ENABLED && BRAINPOOLP384T1_SUPPORT != DISABLED)
   #error BRAINPOOLP384T1_SUPPORT parameter is not valid
#endif

//brainpoolP512r1 elliptic curve support
#ifndef BRAINPOOLP512R1_SUPPORT
   #define BRAINPOOLP512R1_SUPPORT DISABLED
#elif (BRAINPOOLP512R1_SUPPORT != ENABLED && BRAINPOOLP512R1_SUPPORT != DISABLED)
   #error BRAINPOOLP512R1_SUPPORT parameter is not valid
#endif

//brainpoolP512t1 elliptic curve support
#ifndef BRAINPOOLP512T1_SUPPORT
   #define BRAINPOOLP512T1_SUPPORT DISABLED
#elif (BRAINPOOLP512T1_SUPPORT != ENABLED && BRAINPOOLP512T1_SUPPORT != DISABLED)
   #error BRAINPOOLP512T1_SUPPORT parameter is not valid
#endif

//FRP256v1 elliptic curve support
#ifndef FRP256V1_SUPPORT
   #define FRP256V1_SUPPORT DISABLED
#elif (FRP256V1_SUPPORT != ENABLED && FRP256V1_SUPPORT != DISABLED)
   #error FRP256V1_SUPPORT parameter is not valid
#endif

//SM2 elliptic curve support
#ifndef SM2_SUPPORT
   #define SM2_SUPPORT DISABLED
#elif (SM2_SUPPORT != ENABLED && SM2_SUPPORT != DISABLED)
   #error SM2_SUPPORT parameter is not valid
#endif

//Curve25519 elliptic curve support
#ifndef X25519_SUPPORT
   #define X25519_SUPPORT DISABLED
#elif (X25519_SUPPORT != ENABLED && X25519_SUPPORT != DISABLED)
   #error X25519_SUPPORT parameter is not valid
#endif

//Curve448 elliptic curve support
#ifndef X448_SUPPORT
   #define X448_SUPPORT DISABLED
#elif (X448_SUPPORT != ENABLED && X448_SUPPORT != DISABLED)
   #error X448_SUPPORT parameter is not valid
#endif

//Ed25519 elliptic curve support
#ifndef ED25519_SUPPORT
   #define ED25519_SUPPORT DISABLED
#elif (ED25519_SUPPORT != ENABLED && ED25519_SUPPORT != DISABLED)
   #error ED25519_SUPPORT parameter is not valid
#endif

//Ed448 elliptic curve support
#ifndef ED448_SUPPORT
   #define ED448_SUPPORT DISABLED
#elif (ED448_SUPPORT != ENABLED && ED448_SUPPORT != DISABLED)
   #error ED448_SUPPORT parameter is not valid
#endif

//Maximum size of prime modulus p
#if (SECP521R1_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 17
#elif (BRAINPOOLP512R1_SUPPORT == ENABLED || BRAINPOOLP512T1_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 16
#elif (X448_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 14
#elif (SECP384R1_SUPPORT == ENABLED || BRAINPOOLP384R1_SUPPORT == ENABLED || \
   BRAINPOOLP384T1_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 12
#elif (BRAINPOOLP320R1_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 10
#elif (SECP256K1_SUPPORT == ENABLED || SECP256R1_SUPPORT == ENABLED || \
   BRAINPOOLP256R1_SUPPORT == ENABLED || BRAINPOOLP256T1_SUPPORT == ENABLED || \
   FRP256V1_SUPPORT == ENABLED || SM2_SUPPORT == ENABLED || \
   X25519_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 8
#elif (SECP224K1_SUPPORT == ENABLED || SECP224R1_SUPPORT == ENABLED || \
   BRAINPOOLP224R1_SUPPORT == ENABLED || BRAINPOOLP224T1_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 7
#elif (SECP192K1_SUPPORT == ENABLED || SECP192R1_SUPPORT == ENABLED || \
   BRAINPOOLP192R1_SUPPORT == ENABLED || BRAINPOOLP192T1_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 6
#elif (SECP160K1_SUPPORT == ENABLED || SECP160R1_SUPPORT == ENABLED || \
   SECP160R2_SUPPORT == ENABLED || BRAINPOOLP160R1_SUPPORT == ENABLED || \
   BRAINPOOLP160T1_SUPPORT == ENABLED)
   #define EC_MAX_MODULUS_SIZE 5
#else
   #define EC_MAX_MODULUS_SIZE 4
#endif

//Maximum size of order q
#if (SECP521R1_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 17
#elif (BRAINPOOLP512R1_SUPPORT == ENABLED || BRAINPOOLP512T1_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 16
#elif (X448_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 14
#elif (SECP384R1_SUPPORT == ENABLED || BRAINPOOLP384R1_SUPPORT == ENABLED || \
   BRAINPOOLP384T1_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 12
#elif (BRAINPOOLP320R1_SUPPORT == ENABLED || BRAINPOOLP320T1_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 10
#elif (SECP224K1_SUPPORT == ENABLED || SECP256K1_SUPPORT == ENABLED || \
   SECP256R1_SUPPORT == ENABLED || BRAINPOOLP256R1_SUPPORT == ENABLED || \
   BRAINPOOLP256T1_SUPPORT == ENABLED || FRP256V1_SUPPORT == ENABLED || \
   SM2_SUPPORT == ENABLED || X25519_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 8
#elif (SECP224R1_SUPPORT == ENABLED || BRAINPOOLP224R1_SUPPORT == ENABLED || \
   BRAINPOOLP224T1_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 7
#elif (SECP160K1_SUPPORT == ENABLED || SECP160R1_SUPPORT == ENABLED || \
   SECP160R2_SUPPORT == ENABLED || SECP192K1_SUPPORT == ENABLED || \
   SECP192R1_SUPPORT == ENABLED || BRAINPOOLP192R1_SUPPORT == ENABLED || \
   BRAINPOOLP192T1_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 6
#elif (BRAINPOOLP160R1_SUPPORT == ENABLED || BRAINPOOLP160T1_SUPPORT == ENABLED)
   #define EC_MAX_ORDER_SIZE 5
#else
   #define EC_MAX_ORDER_SIZE 4
#endif

//Forward declaration of EcCurve structure
struct _EcCurve;
#define EcCurve struct _EcCurve

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Elliptic curve type
 **/

typedef enum
{
   EC_CURVE_TYPE_WEIERSTRASS    = 1,
   EC_CURVE_TYPE_WEIERSTRASS_A0 = 2,
   EC_CURVE_TYPE_WEIERSTRASS_A3 = 3,
   EC_CURVE_TYPE_MONTGOMERY     = 4,
   EC_CURVE_TYPE_EDWARDS        = 5
} EcCurveType;


/**
 * @brief EC point format
 **/

typedef enum
{
   EC_POINT_FORMAT_COMPRESSED_EVEN = 0x02,
   EC_POINT_FORMAT_COMPRESSED_ODD  = 0x03,
   EC_POINT_FORMAT_UNCOMPRESSED    = 0x04
} EcPointFormat;


/**
 * @brief EC public key format
 **/

typedef enum
{
   EC_PUBLIC_KEY_FORMAT_X963  = 0,
   EC_PUBLIC_KEY_FORMAT_RAW   = 1,
   EC_PUBLIC_KEY_FORMAT_RAW_X = 2,
   EC_PUBLIC_KEY_FORMAT_RAW_Y = 3
} EcPublicKeyFormat;


/**
 * @brief EC point (affine coordinates)
 **/

typedef struct
{
   uint32_t x[EC_MAX_MODULUS_SIZE]; ///<x-coordinate
   uint32_t y[EC_MAX_MODULUS_SIZE]; ///<y-coordinate
} EcPoint;


/**
 * @brief EC point (projective coordinates)
 **/

typedef struct
{
   uint32_t x[EC_MAX_MODULUS_SIZE]; ///<x-coordinate
   uint32_t y[EC_MAX_MODULUS_SIZE]; ///<y-coordinate
   uint32_t z[EC_MAX_MODULUS_SIZE]; ///<z-coordinate
} EcPoint3;


/**
 * @brief EC public key
 **/

typedef struct
{
   const EcCurve *curve; ///<Elliptic curve parameters
   EcPoint q;            ///<Public key
} EcPublicKey;


/**
 * @brief EC private key
 **/

typedef struct
{
   const EcCurve *curve;          ///<Elliptic curve parameters
   uint32_t d[EC_MAX_ORDER_SIZE]; ///<Private key
   int_t slot;                    ///<Private key slot
   EcPublicKey q;                 ///<Public key
} EcPrivateKey;


/**
 * @brief Working state (point addition/subtraction/doubling)
 **/

typedef struct
{
   const EcCurve *curve;
   uint32_t t0[EC_MAX_MODULUS_SIZE];
   uint32_t t1[EC_MAX_MODULUS_SIZE];
   uint32_t t2[EC_MAX_MODULUS_SIZE];
   uint32_t t3[EC_MAX_MODULUS_SIZE];
   uint32_t t4[EC_MAX_MODULUS_SIZE];
   uint32_t t5[EC_MAX_MODULUS_SIZE];
   uint32_t t6[EC_MAX_MODULUS_SIZE];
   uint32_t t7[EC_MAX_MODULUS_SIZE];
} EcState;


/**
 * @brief Working state (fast scalar multiplication)
 **/

typedef struct
{
   uint32_t k[EC_MAX_ORDER_SIZE + 1];
   uint32_t h[EC_MAX_ORDER_SIZE + 1];
   EcState subState;
} EcMulFastState;


/**
 * @brief Working state (regular scalar multiplication)
 **/

typedef struct
{
   uint32_t init;
   EcPoint3 p0;
   EcPoint3 q0;
   EcPoint3 p;
   EcPoint3 q;
   EcState subState;
} EcMulRegularState;


/**
 * @brief Working state (twin multiplication)
 **/

typedef struct
{
   EcPoint3 spt;
   EcPoint3 smt;
   EcState subState;
} EcTwinMulState;


/**
 * @brief Modular reduction
 **/

typedef void (*EcModAlgo)(const EcCurve *curve, uint32_t *r,
   const uint32_t *a);


/**
 * @brief Modular inverse
 **/

typedef void (*EcInvModAlgo)(const EcCurve *curve, uint32_t *r,
   const uint32_t *a);


/**
 * @brief Elliptic curve parameters
 **/

struct _EcCurve
{
   const char_t *name;                          ///<Curve name
   const uint8_t *oid;                          ///<Object identifier
   size_t oidSize;                              ///<OID size
   EcCurveType type;                            ///<Curve type
   uint_t fieldSize;                            ///<Field size, in bits
   uint_t orderSize;                            ///<Order size, in bits
   const uint32_t p[EC_MAX_MODULUS_SIZE + 1];   ///<Prime modulus p
   const uint32_t pmu[EC_MAX_MODULUS_SIZE + 1]; ///<Pre-computed value mu
   const uint32_t a[EC_MAX_MODULUS_SIZE];       ///<Curve parameter a
   const uint32_t b[EC_MAX_MODULUS_SIZE];       ///<Curve parameter b
   EcPoint3 g;                                  ///<Base point G
   const uint32_t q[EC_MAX_ORDER_SIZE + 1];     ///<Order of the base point G
   const uint32_t qmu[EC_MAX_ORDER_SIZE + 1];   ///<Pre-computed value mu
   uint32_t h;                                  ///<Cofactor h
   EcModAlgo fieldMod;                          ///<Field modular reduction
   EcInvModAlgo fieldInv;                       ///<Field modular inversion
   EcModAlgo scalarMod;                         ///<Scalar modular reduction
   EcInvModAlgo scalarInv;                      ///<Scalar modular inversion
};


//EC related constants
extern const uint8_t EC_PUBLIC_KEY_OID[7];

//EC related functions
void ecInitPublicKey(EcPublicKey *key);
void ecFreePublicKey(EcPublicKey *key);

void ecInitPrivateKey(EcPrivateKey *key);
void ecFreePrivateKey(EcPrivateKey *key);

error_t ecGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EcPrivateKey *privateKey, EcPublicKey *publicKey);

error_t ecGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EcPrivateKey *privateKey);

error_t ecGeneratePublicKey(const EcPrivateKey *privateKey,
   EcPublicKey *publicKey);

error_t ecImportPublicKey(EcPublicKey *key, const EcCurve *curve,
   const uint8_t *input, size_t length, EcPublicKeyFormat format);

error_t ecExportPublicKey(const EcPublicKey *key, uint8_t *output,
   size_t *written, EcPublicKeyFormat format);

error_t ecImportPrivateKey(EcPrivateKey *key, const EcCurve *curve,
   const uint8_t *input, size_t length);

error_t ecExportPrivateKey(const EcPrivateKey *key, uint8_t *output,
   size_t *written);

error_t ecImportPoint(const EcCurve *curve, EcPoint *r, const uint8_t *input,
   size_t length);

error_t ecExportPoint(const EcCurve *curve, const EcPoint *a, uint8_t *output,
   size_t *written);

void ecProjectify(const EcCurve *curve, EcPoint3 *r, const EcPoint *s);
error_t ecAffinify(const EcCurve *curve, EcPoint3 *r, const EcPoint3 *s);
bool_t ecIsPointAffine(const EcCurve *curve, const EcPoint *s);

void ecDouble(EcState *state, EcPoint3 *r, const EcPoint3 *s);

void ecAdd(EcState *state, EcPoint3 *r, const EcPoint3 *s,
   const EcPoint3 *t);

void ecFullAdd(EcState *state, EcPoint3 *r, const EcPoint3 *s,
   const EcPoint3 *t);

void ecFullSub(EcState *state, EcPoint3 *r, const EcPoint3 *s,
   const EcPoint3 *t);

error_t ecMulFast(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s);

error_t ecMulRegular(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s);

error_t ecTwinMul(const EcCurve *curve, EcPoint3 *r, const uint32_t *d0,
   const EcPoint3 *s, const uint32_t *d1, const EcPoint3 *t);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
