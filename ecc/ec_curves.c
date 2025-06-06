/**
 * @file ec_curves.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"
#include "ecc/ec_curves.h"
#include "ecc/ec_misc.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (EC_SUPPORT == ENABLED)

//secp112r1 OID (1.3.132.0.6)
const uint8_t SECP112R1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x06};
//secp112r2 OID (1.3.132.0.7)
const uint8_t SECP112R2_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x07};
//secp128r1 OID (1.3.132.0.28)
const uint8_t SECP128R1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x1C};
//secp128r2 OID (1.3.132.0.29)
const uint8_t SECP128R2_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x1D};
//secp160k1 OID (1.3.132.0.9)
const uint8_t SECP160K1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x09};
//secp160r1 OID (1.3.132.0.8)
const uint8_t SECP160R1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x08};
//secp160r2 OID (1.3.132.0.30)
const uint8_t SECP160R2_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x1E};
//secp192k1 OID (1.3.132.0.31)
const uint8_t SECP192K1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x1F};
//secp192r1 OID (1.2.840.10045.3.1.1)
const uint8_t SECP192R1_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01};
//secp224k1 OID (1.3.132.0.32)
const uint8_t SECP224K1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x20};
//secp224r1 OID (1.3.132.0.33)
const uint8_t SECP224R1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x21};
//secp256k1 OID (1.3.132.0.10)
const uint8_t SECP256K1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x0A};
//secp256r1 OID (1.2.840.10045.3.1.7)
const uint8_t SECP256R1_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
//secp384r1 OID (1.3.132.0.34)
const uint8_t SECP384R1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x22};
//secp521r1 OID (1.3.132.0.35)
const uint8_t SECP521R1_OID[5] = {0x2B, 0x81, 0x04, 0x00, 0x23};
//brainpoolP160r1 OID (1.3.36.3.3.2.8.1.1.1)
const uint8_t BRAINPOOLP160R1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01};
//brainpoolP160t1 OID (1.3.36.3.3.2.8.1.1.2)
const uint8_t BRAINPOOLP160T1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02};
//brainpoolP192r1 OID (1.3.36.3.3.2.8.1.1.3)
const uint8_t BRAINPOOLP192R1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03};
//brainpoolP192t1 OID (1.3.36.3.3.2.8.1.1.4)
const uint8_t BRAINPOOLP192T1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04};
//brainpoolP224r1 OID (1.3.36.3.3.2.8.1.1.5)
const uint8_t BRAINPOOLP224R1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05};
//brainpoolP224t1 OID (1.3.36.3.3.2.8.1.1.6)
const uint8_t BRAINPOOLP224T1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06};
//brainpoolP256r1 OID (1.3.36.3.3.2.8.1.1.7)
const uint8_t BRAINPOOLP256R1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
//brainpoolP256t1 OID (1.3.36.3.3.2.8.1.1.8)
const uint8_t BRAINPOOLP256T1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08};
//brainpoolP320r1 OID (1.3.36.3.3.2.8.1.1.9)
const uint8_t BRAINPOOLP320R1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09};
//brainpoolP320t1 OID (1.3.36.3.3.2.8.1.1.10)
const uint8_t BRAINPOOLP320T1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0A};
//brainpoolP384r1 OID (1.3.36.3.3.2.8.1.1.11)
const uint8_t BRAINPOOLP384R1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B};
//brainpoolP384t1 OID (1.3.36.3.3.2.8.1.1.12)
const uint8_t BRAINPOOLP384T1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0C};
//brainpoolP512r1 OID (1.3.36.3.3.2.8.1.1.13)
const uint8_t BRAINPOOLP512R1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D};
//brainpoolP512t1 OID (1.3.36.3.3.2.8.1.1.14)
const uint8_t BRAINPOOLP512T1_OID[9] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0E};
//FRP256v1 OID (1.2.250.1.223.101.256.1)
const uint8_t FRP256V1_OID[10] = {0x2A, 0x81, 0x7A, 0x01, 0x81, 0x5F, 0x65, 0x82, 0x00, 0x01};
//SM2 OID (1.2.156.10197.1.301)
const uint8_t SM2_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D};
//X25519 OID (1.3.101.110)
const uint8_t X25519_OID[3] = {0x2B, 0x65, 0x6E};
//X448 OID (1.3.101.111)
const uint8_t X448_OID[3] = {0x2B, 0x65, 0x6F};
//Ed25519 OID (1.3.101.112)
const uint8_t ED25519_OID[3] = {0x2B, 0x65, 0x70};
//Ed448 OID (1.3.101.113)
const uint8_t ED448_OID[3] = {0x2B, 0x65, 0x71};


#if (SECP112R1_SUPPORT == ENABLED)

/**
 * @brief secp112r1 elliptic curve
 **/

const EcCurve secp112r1Curve =
{
   //Curve name
   "secp112r1",
   //Object identifier
   SECP112R1_OID,
   sizeof(SECP112R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   112,
   //Order size, in bits
   112,
   //Prime modulus p
   {0xBEAD208B, 0x5E668076, 0x2ABF62E3, 0x0000DB7C},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xBEAD2088, 0x5E668076, 0x2ABF62E3, 0x0000DB7C},
   //Curve parameter b
   {0x11702B22, 0x16EEDE89, 0xF8BA0439, 0x0000659E},
   //Base point G
   {
      //x-coordinate
      {0xF9C2F098, 0x5EE76B55, 0x7239995A, 0x00000948},
      //y-coordinate
      {0x0FF77500, 0xC0A23E0E, 0xE5AF8724, 0x0000A89C},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xAC6561C5, 0x5E7628DF, 0x2ABF62E3, 0x0000DB7C},
   //Pre-computed value mu
   {0x46B3447E, 0xFFEAB2EA, 0xFFFFFFFF, 0x00012A96},
   //Cofactor
   1,
   //Field modular reduction
   secp112r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   secp112r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP112R2_SUPPORT == ENABLED)

/**
 * @brief secp112r2 elliptic curve
 **/

const EcCurve secp112r2Curve =
{
   //Curve name
   "secp112r2",
   //Object identifier
   SECP112R2_OID,
   sizeof(SECP112R2_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   112,
   //Order size, in bits
   110,
   //Prime modulus p
   {0xBEAD208B, 0x5E668076, 0x2ABF62E3, 0x0000DB7C},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x5C0EF02C, 0x8A0AAAF6, 0xC24C05F3, 0x00006127},
   //Curve parameter b
   {0x4C85D709, 0xED74FCC3, 0xF1815DB5, 0x000051DE},
   //Base point G
   {
      //x-coordinate
      {0xD0928643, 0xB4E1649D, 0x0AB5E892, 0x00004BA3},
      //y-coordinate
      {0x6E956E97, 0x3747DEF3, 0x46F5882E, 0x0000ADCD},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x0520D04B, 0xD7597CA1, 0x0AAFD8B8, 0x000036DF},
   //Pre-computed value mu
   {0x95D6F3F0, 0x015D0500, 0x00000000, 0x00012A97},
   //Cofactor
   4,
   //Field modular reduction
   secp112r2FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   secp112r2ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP128R1_SUPPORT == ENABLED)

/**
 * @brief secp128r1 elliptic curve
 **/

const EcCurve secp128r1Curve =
{
   //Curve name
   "secp128r1",
   //Object identifier
   SECP128R1_OID,
   sizeof(SECP128R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   128,
   //Order size, in bits
   128,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD},
   //Curve parameter b
   {0x2CEE5ED3, 0xD824993C, 0x1079F43D, 0xE87579C1},
   //Base point G
   {
      //x-coordinate
      {0xA52C5B86, 0x0C28607C, 0x8B899B2D, 0x161FF752},
      //y-coordinate
      {0xDDED7A83, 0xC02DA292, 0x5BAFEB13, 0xCF5AC839},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x9038A115, 0x75A30D1B, 0x00000000, 0xFFFFFFFE},
   //Pre-computed value mu
   {0x993B2A87, 0x8A5CF2EA, 0x00000003, 0x00000002, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   secp128r1FieldMod,
   //Field modular inversion
   secp128r1FieldInv,
   //Scalar modular reduction
   secp128r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP128R2_SUPPORT == ENABLED)

/**
 * @brief secp128r2 elliptic curve
 **/

const EcCurve secp128r2Curve =
{
   //Curve name
   "secp128r2",
   //Object identifier
   SECP128R2_OID,
   sizeof(SECP128R2_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   128,
   //Order size, in bits
   126,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xBFF9AEE1, 0xBF59CC9B, 0xD1B3BBFE, 0xD6031998},
   //Curve parameter b
   {0xBB6D8A5D, 0xDC2C6558, 0x80D02919, 0x5EEEFCA3},
   //Base point G
   {
      //x-coordinate
      {0xCDEBC140, 0xE6FB32A7, 0x5E572983, 0x7B6AA5D8},
      //y-coordinate
      {0x5FC34B44, 0x7106FE80, 0x894D3AEE, 0x27B6916A},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x0613B5A3, 0xBE002472, 0x7FFFFFFF, 0x3FFFFFFF},
   //Pre-computed value mu
   {0x07AEE271, 0x07FF6E44, 0x00000005, 0x00000002, 0x00000001},
   //Cofactor
   4,
   //Field modular reduction
   secp128r2FieldMod,
   //Field modular inversion
   secp128r2FieldInv,
   //Scalar modular reduction
   secp128r2ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP160K1_SUPPORT == ENABLED)

/**
 * @brief secp160k1 elliptic curve
 **/

const EcCurve secp160k1Curve =
{
   //Curve name
   "secp160k1",
   //Object identifier
   SECP160K1_OID,
   sizeof(SECP160K1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A0,
   //Field size, in bits
   160,
   //Order size, in bits
   161,
   //Prime modulus p
   {0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x00000000},
   //Curve parameter b
   {0x00000007},
   //Base point G
   {
      //x-coordinate
      {0xDD4D7EBB, 0x3036F4F5, 0xA4019E76, 0xE37AA192, 0x3B4C382C},
      //y-coordinate
      {0xF03C4FEE, 0x531733C3, 0x6BC28286, 0x318FDCED, 0x938CF935},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xCA16B6B3, 0x16DFAB9A, 0x0001B8FA, 0x00000000, 0x00000000, 0x00000001},
   //Pre-computed value mu
   {0x929FEF39, 0xA8CA6BD2, 0x8E0BD240, 0xFFFFFFFC, 0xFFFFFFFF, 0x0001FFFF},
   //Cofactor
   1,
   //Field modular reduction
   secp160k1FieldMod,
   //Field modular inversion
   secp160k1FieldInv,
   //Scalar modular reduction
   secp160k1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP160R1_SUPPORT == ENABLED)

/**
 * @brief secp160r1 elliptic curve
 **/

const EcCurve secp160r1Curve =
{
   //Curve name
   "secp160r1",
   //Object identifier
   SECP160R1_OID,
   sizeof(SECP160R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   160,
   //Order size, in bits
   161,
   //Prime modulus p
   {0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x7FFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Curve parameter b
   {0xC565FA45, 0x81D4D4AD, 0x65ACF89F, 0x54BD7A8B, 0x1C97BEFC},
   //Base point G
   {
      //x-coordinate
      {0x13CBFC82, 0x68C38BB9, 0x46646989, 0x8EF57328, 0x4A96B568},
      //y-coordinate
      {0x7AC5FB32, 0x04235137, 0x59DCC912, 0x3168947D, 0x23A62855},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xCA752257, 0xF927AED3, 0x0001F4C8, 0x00000000, 0x00000000, 0x00000001},
   //Pre-computed value mu
   {0xBB59A743, 0xA2586B15, 0x166E0DB0, 0xFFFFFFFC, 0xFFFFFFFF, 0x0001FFFF},
   //Cofactor
   1,
   //Field modular reduction
   secp160r1FieldMod,
   //Field modular inversion
   secp160r1FieldInv,
   //Scalar modular reduction
   secp160r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP160R2_SUPPORT == ENABLED)

/**
 * @brief secp160r2 elliptic curve
 **/

const EcCurve secp160r2Curve =
{
   //Curve name
   "secp160r2",
   //Object identifier
   SECP160R2_OID,
   sizeof(SECP160R2_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   160,
   //Order size, in bits
   161,
   //Prime modulus p
   {0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFAC70, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Curve parameter b
   {0xF50388BA, 0x04664D5A, 0xAB572749, 0xFB59EB8B, 0xB4E134D3},
   //Base point G
   {
      //x-coordinate
      {0x3144CE6D, 0x30F7199D, 0x1F4FF11B, 0x293A117E, 0x52DCB034},
      //y-coordinate
      {0xA7D43F2E, 0xF9982CFE, 0xE071FA0D, 0xE331F296, 0xFEAFFEF2},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xF3A1A16B, 0xE786A818, 0x0000351E, 0x00000000, 0x00000000, 0x00000001},
   //Pre-computed value mu
   {0xBD2A160B, 0xAFCE18BC, 0x95C230F2, 0xFFFFFFFF, 0xFFFFFFFF, 0x0001FFFF},
   //Cofactor
   1,
   //Field modular reduction
   secp160r2FieldMod,
   //Field modular inversion
   secp160r2FieldInv,
   //Scalar modular reduction
   secp160r2ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP192K1_SUPPORT == ENABLED)

/**
 * @brief secp192k1 elliptic curve
 **/

const EcCurve secp192k1Curve =
{
   //Curve name
   "secp192k1",
   //Object identifier
   SECP192K1_OID,
   sizeof(SECP192K1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A0,
   //Field size, in bits
   192,
   //Order size, in bits
   192,
   //Prime modulus p
   {0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x00000000},
   //Curve parameter b
   {0x00000003},
   //Base point G
   {
      //x-coordinate
      {0xEAE06C7D, 0x1DA5D1B1, 0x80B7F434, 0x26B07D02, 0xC057E9AE, 0xDB4FF10E},
      //y-coordinate
      {0xD95E2F9D, 0x4082AA88, 0x15BE8634, 0x844163D0, 0x9C5628A7, 0x9B2F2F6D},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x74DEFD8D, 0x0F69466A, 0x26F2FC17, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0x8B210276, 0xF096B995, 0xD90D03E8, 0x00000001, 0x00000000, 0x00000000, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   secp192k1FieldMod,
   //Field modular inversion
   secp192k1FieldInv,
   //Scalar modular reduction
   secp192k1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP192R1_SUPPORT == ENABLED)

/**
 * @brief secp192r1 elliptic curve
 **/

const EcCurve secp192r1Curve =
{
   //Curve name
   "secp192r1",
   //Object identifier
   SECP192R1_OID,
   sizeof(SECP192R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   192,
   //Order size, in bits
   192,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Curve parameter b
   {0xC146B9B1, 0xFEB8DEEC, 0x72243049, 0x0FA7E9AB, 0xE59C80E7, 0x64210519},
   //Base point G
   {
      //x-coordinate
      {0x82FF1012, 0xF4FF0AFD, 0x43A18800, 0x7CBF20EB, 0xB03090F6, 0x188DA80E},
      //y-coordinate
      {0x1E794811, 0x73F977A1, 0x6B24CDD5, 0x631011ED, 0xFFC8DA78, 0x07192B95},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xB4D22831, 0x146BC9B1, 0x99DEF836, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0x4B2DD7CF, 0xEB94364E, 0x662107C9, 0x00000000, 0x00000000, 0x00000000, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   secp192r1FieldMod,
   //Field modular inversion
   secp192r1FieldInv,
   //Scalar modular reduction
   secp192r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP224K1_SUPPORT == ENABLED)

/**
 * @brief secp224k1 elliptic curve
 **/

const EcCurve secp224k1Curve =
{
   //Curve name
   "secp224k1",
   //Object identifier
   SECP224K1_OID,
   sizeof(SECP224K1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A0,
   //Field size, in bits
   224,
   //Order size, in bits
   225,
   //Prime modulus p
   {0xFFFFE56D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x00000000},
   //Curve parameter b
   {0x00000005},
   //Base point G
   {
      //x-coordinate
      {0xB6B7A45C, 0x0F7E650E, 0xE47075A9, 0x69A467E9, 0x30FC28A1, 0x4DF099DF, 0xA1455B33},
      //y-coordinate
      {0x556D61A5, 0xE2CA4BDB, 0xC0B0BD59, 0xF7E319F7, 0x82CAFBD6, 0x7FBA3442, 0x7E089FED},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x769FB1F7, 0xCAF0A971, 0xD2EC6184, 0x0001DCE8, 0x00000000, 0x00000000, 0x00000000, 0x00000001},
   //Pre-computed value mu
   {0x9C18F0E5, 0xAD1D12C0, 0x3CF66A1E, 0x462E5A27, 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x0001FFFF},
   //Cofactor
   1,
   //Field modular reduction
   secp224k1FieldMod,
   //Field modular inversion
   secp224k1FieldInv,
   //Scalar modular reduction
   secp224k1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP224R1_SUPPORT == ENABLED)

/**
 * @brief secp224r1 elliptic curve
 **/

const EcCurve secp224r1Curve =
{
   //Curve name
   "secp224r1",
   //Object identifier
   SECP224R1_OID,
   sizeof(SECP224R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   224,
   //Order size, in bits
   224,
   //Prime modulus p
   {0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Curve parameter b
   {0x2355FFB4, 0x270B3943, 0xD7BFD8BA, 0x5044B0B7, 0xF5413256, 0x0C04B3AB, 0xB4050A85},
   //Base point G
   {
      //x-coordinate
      {0x115C1D21, 0x343280D6, 0x56C21122, 0x4A03C1D3, 0x321390B9, 0x6BB4BF7F, 0xB70E0CBD},
      //y-coordinate
      {0x85007E34, 0x44D58199, 0x5A074764, 0xCD4375A0, 0x4C22DFE6, 0xB5F723FB, 0xBD376388},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x5C5C2A3D, 0x13DD2945, 0xE0B8F03E, 0xFFFF16A2, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0xA3A3D5C3, 0xEC22D6BA, 0x1F470FC1, 0x0000E95D, 0x00000000, 0x00000000, 0x00000000, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   secp224r1FieldMod,
   //Field modular inversion
   secp224r1FieldInv,
   //Scalar modular reduction
   secp224r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP256K1_SUPPORT == ENABLED)

/**
 * @brief secp256k1 elliptic curve
 **/

const EcCurve secp256k1Curve =
{
   //Curve name
   "secp256k1",
   //Object identifier
   SECP256K1_OID,
   sizeof(SECP256K1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A0,
   //Field size, in bits
   256,
   //Order size, in bits
   256,
   //Prime modulus p
   {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x00000000},
   //Curve parameter b
   {0x00000007},
   //Base point G
   {
      //x-coordinate
      {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E},
      //y-coordinate
      {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0x2FC9BEC0, 0x402DA173, 0x50B75FC4, 0x45512319, 0x00000001, 0x00000000, 0x00000000, 0x00000000,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   secp256k1FieldMod,
   //Field modular inversion
   secp256k1FieldInv,
   //Scalar modular reduction
   secp256k1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP256R1_SUPPORT == ENABLED)

/**
 * @brief secp256r1 elliptic curve
 **/

const EcCurve secp256r1Curve =
{
   //Curve name
   "secp256r1",
   //Object identifier
   SECP256R1_OID,
   sizeof(SECP256R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   256,
   //Order size, in bits
   256,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
   //Curve parameter b
   {0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8},
   //Base point G
   {
      //x-coordinate
      {0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2},
      //y-coordinate
      {0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357, 0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF},
   //Pre-computed value mu
   {0xEEDF9BFE, 0x012FFD85, 0xDF1A6C21, 0x43190552, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   secp256r1FieldMod,
   //Field modular inversion
   secp256r1FieldInv,
   //Scalar modular reduction
   secp256r1ScalarMod,
   //Scalar modular inversion
   secp256r1ScalarInv,
};

#endif
#if (SECP384R1_SUPPORT == ENABLED)

/**
 * @brief secp384r1 elliptic curve
 **/

const EcCurve secp384r1Curve =
{
   //Curve name
   "secp384r1",
   //Object identifier
   SECP384R1_OID,
   sizeof(SECP384R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   384,
   //Order size, in bits
   384,
   //Prime modulus p
   {0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFFC, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Curve parameter b
   {0xD3EC2AEF, 0x2A85C8ED, 0x8A2ED19D, 0xC656398D, 0x5013875A, 0x0314088F, 0xFE814112, 0x181D9C6E,
    0xE3F82D19, 0x988E056B, 0xE23EE7E4, 0xB3312FA7},
   //Base point G
   {
      //x-coordinate
      {0x72760AB7, 0x3A545E38, 0xBF55296C, 0x5502F25D, 0x82542A38, 0x59F741E0, 0x8BA79B98, 0x6E1D3B62,
       0xF320AD74, 0x8EB1C71E, 0xBE8B0537, 0xAA87CA22},
      //y-coordinate
      {0x90EA0E5F, 0x7A431D7C, 0x1D7E819D, 0x0A60B1CE, 0xB5F0B8C0, 0xE9DA3113, 0x289A147C, 0xF8F41DBD,
       0x9292DC29, 0x5D9E98BF, 0x96262C6F, 0x3617DE4A},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xCCC52973, 0xECEC196A, 0x48B0A77A, 0x581A0DB2, 0xF4372DDF, 0xC7634D81, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0x333AD68D, 0x1313E695, 0xB74F5885, 0xA7E5F24D, 0x0BC8D220, 0x389CB27E, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   secp384r1FieldMod,
   //Field modular inversion
   secp384r1FieldInv,
   //Scalar modular reduction
   secp384r1ScalarMod,
   //Scalar modular inversion
   secp384r1ScalarInv,
};

#endif
#if (SECP521R1_SUPPORT == ENABLED)

/**
 * @brief secp521r1 elliptic curve
 **/

const EcCurve secp521r1Curve =
{
   //Curve name
   "secp521r1",
   //Object identifier
   SECP521R1_OID,
   sizeof(SECP521R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   521,
   //Order size, in bits
   521,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0x000001FF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0x000001FF},
   //Curve parameter b
   {0x6B503F00, 0xEF451FD4, 0x3D2C34F1, 0x3573DF88, 0x3BB1BF07, 0x1652C0BD, 0xEC7E937B, 0x56193951,
    0x8EF109E1, 0xB8B48991, 0x99B315F3, 0xA2DA725B, 0xB68540EE, 0x929A21A0, 0x8E1C9A1F, 0x953EB961,
    0x00000051},
   //Base point G
   {
      //x-coordinate
      {0xC2E5BD66, 0xF97E7E31, 0x856A429B, 0x3348B3C1, 0xA2FFA8DE, 0xFE1DC127, 0xEFE75928, 0xA14B5E77,
       0x6B4D3DBA, 0xF828AF60, 0x053FB521, 0x9C648139, 0x2395B442, 0x9E3ECB66, 0x0404E9CD, 0x858E06B7,
       0x000000C6},
      //y-coordinate
      {0x9FD16650, 0x88BE9476, 0xA272C240, 0x353C7086, 0x3FAD0761, 0xC550B901, 0x5EF42640, 0x97EE7299,
       0x273E662C, 0x17AFBD17, 0x579B4468, 0x98F54449, 0x2C7D1BD9, 0x5C8A5FB4, 0x9A3BC004, 0x39296A78,
       0x00000118},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x91386409, 0xBB6FB71E, 0x899C47AE, 0x3BB5C9B8, 0xF709A5D0, 0x7FCC0148, 0xBF2F966B, 0x51868783,
    0xFFFFFFFA, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0x000001FF},
   //Pre-computed value mu
   {0x63CDFB88, 0x482470B7, 0x31DC28A2, 0x251B23BB, 0x7B2D17E2, 0x19FF5B84, 0x6834CA40, 0x3CBC3E20,
    0x000002D7, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00010000},
   //Cofactor
   1,
   //Field modular reduction
   secp521r1FieldMod,
   //Field modular inversion
   secp521r1FieldInv,
   //Scalar modular reduction
   secp521r1ScalarMod,
   //Scalar modular inversion
   secp521r1ScalarInv,
};

#endif
#if (BRAINPOOLP160R1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP160r1 elliptic curve
 **/

const EcCurve brainpoolP160r1Curve =
{
   //Curve name
   "brainpoolP160r1",
   //Object identifier
   BRAINPOOLP160R1_OID,
   sizeof(BRAINPOOLP160R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   160,
   //Order size, in bits
   160,
   //Prime modulus p
   {0x9515620F, 0x95B3D813, 0x60DFC7AD, 0x737059DC, 0xE95E4A5F},
   //Pre-computed value mu
   {0xC26FB1EF, 0xA5D79737, 0xF1269FF8, 0x86396600, 0x18D392ED, 0x00000001},
   //Curve parameter a
   {0xE8F7C300, 0xDA745D97, 0xE2BE61BA, 0xA280EB74, 0x340E7BE2},
   //Curve parameter b
   {0xD8675E58, 0xBDEC95C8, 0x134FAA2D, 0x95423412, 0x1E589A85},
   //Base point G
   {
      //x-coordinate
      {0xBDBCDBC3, 0x31EB5AF7, 0x62938C46, 0xEA3F6A4F, 0xBED5AF16},
      //y-coordinate
      {0x16DA6321, 0x669C9763, 0x38F94741, 0x7A1A8EC3, 0x1667CB47},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x9E60FC09, 0xD4502940, 0x60DF5991, 0x737059DC, 0xE95E4A5F},
   //Pre-computed value mu
   {0x033BC7E6, 0xB54E9909, 0xF1272478, 0x86396600, 0x18D392ED, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP160r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP160r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP160T1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP160t1 elliptic curve
 **/

const EcCurve brainpoolP160t1Curve =
{
   //Curve name
   "brainpoolP160t1",
   //Object identifier
   BRAINPOOLP160T1_OID,
   sizeof(BRAINPOOLP160T1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   160,
   //Order size, in bits
   160,
   //Prime modulus p
   {0x9515620F, 0x95B3D813, 0x60DFC7AD, 0x737059DC, 0xE95E4A5F},
   //Pre-computed value mu
   {0xC26FB1EF, 0xA5D79737, 0xF1269FF8, 0x86396600, 0x18D392ED, 0x00000001},
   //Curve parameter a
   {0x9515620C, 0x95B3D813, 0x60DFC7AD, 0x737059DC, 0xE95E4A5F},
   //Curve parameter b
   {0x5C55F380, 0x7DAA7A0B, 0x51ED2C4D, 0xAE535B7B, 0x7A556B6D},
   //Base point G
   {
      //x-coordinate
      {0x65FF2378, 0xEB05ACC2, 0x397E64BA, 0x9B34EFC1, 0xB199B13B},
      //y-coordinate
      {0x52C9E0AD, 0x24437721, 0xF0991B84, 0x7C7C1961, 0xADD6718B},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x9E60FC09, 0xD4502940, 0x60DF5991, 0x737059DC, 0xE95E4A5F},
   //Pre-computed value mu
   {0x033BC7E6, 0xB54E9909, 0xF1272478, 0x86396600, 0x18D392ED, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP160t1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP160t1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP192R1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP192r1 elliptic curve
 **/

const EcCurve brainpoolP192r1Curve =
{
   //Curve name
   "brainpoolP192r1",
   //Object identifier
   BRAINPOOLP192R1_OID,
   sizeof(BRAINPOOLP192R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   192,
   //Order size, in bits
   192,
   //Prime modulus p
   {0xE1A86297, 0x8FCE476D, 0x93D18DB7, 0xA7A34630, 0x932A36CD, 0xC302F41D},
   //Pre-computed value mu
   {0x10B1AC0A, 0x6639FECF, 0xC2462077, 0x675BC2FD, 0xFF1728C8, 0x500FEA39, 0x00000001},
   //Curve parameter a
   {0xC69A28EF, 0xCAE040E5, 0xFE8685C1, 0x9C39C031, 0x76B1E0E1, 0x6A911740},
   //Curve parameter b
   {0x6FBF25C9, 0xCA7EF414, 0x4F4496BC, 0xDC721D04, 0x7C28CCA3, 0x469A28EF},
   //Base point G
   {
      //x-coordinate
      {0x53375FD6, 0x0A2F5C48, 0x6CB0F090, 0x53B033C5, 0xAAB6A487, 0xC0A0647E},
      //y-coordinate
      {0xFA299B8F, 0xE6773FA2, 0xC1490002, 0x8B5F4828, 0x6ABD5BB8, 0x14B69086},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x9AC4ACC1, 0x5BE8F102, 0x9E9E916B, 0xA7A3462F, 0x932A36CD, 0xC302F41D},
   //Pre-computed value mu
   {0x5E71F108, 0x3A674578, 0x68D2F9A8, 0x675BC2FF, 0xFF1728C8, 0x500FEA39, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP192r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP192r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP192T1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP192t1 elliptic curve
 **/

const EcCurve brainpoolP192t1Curve =
{
   //Curve name
   "brainpoolP192t1",
   //Object identifier
   BRAINPOOLP192T1_OID,
   sizeof(BRAINPOOLP192T1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   192,
   //Order size, in bits
   192,
   //Prime modulus p
   {0xE1A86297, 0x8FCE476D, 0x93D18DB7, 0xA7A34630, 0x932A36CD, 0xC302F41D},
   //Pre-computed value mu
   {0x10B1AC0A, 0x6639FECF, 0xC2462077, 0x675BC2FD, 0xFF1728C8, 0x500FEA39, 0x00000001},
   //Curve parameter a
   {0xE1A86294, 0x8FCE476D, 0x93D18DB7, 0xA7A34630, 0x932A36CD, 0xC302F41D},
   //Curve parameter b
   {0x27897B79, 0xFB68542E, 0x3B35BEC2, 0x68F9DEB4, 0xEC78681E, 0x13D56FFA},
   //Base point G
   {
      //x-coordinate
      {0xF4618129, 0x2C446AF6, 0xBBF43FA7, 0x282E1FE7, 0x82F63C30, 0x3AE9E58C},
      //y-coordinate
      {0x7CCC01C9, 0xB7E5B3DE, 0x449D0084, 0x902AB5CA, 0x67C2223A, 0x097E2C56},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x9AC4ACC1, 0x5BE8F102, 0x9E9E916B, 0xA7A3462F, 0x932A36CD, 0xC302F41D},
   //Pre-computed value mu
   {0x5E71F108, 0x3A674578, 0x68D2F9A8, 0x675BC2FF, 0xFF1728C8, 0x500FEA39, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP192t1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP192t1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP224R1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP224r1 elliptic curve
 **/

const EcCurve brainpoolP224r1Curve =
{
   //Curve name
   "brainpoolP224r1",
   //Object identifier
   BRAINPOOLP224R1_OID,
   sizeof(BRAINPOOLP224R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   224,
   //Order size, in bits
   224,
   //Prime modulus p
   {0x7EC8C0FF, 0x97DA89F5, 0xB09F0757, 0x75D1D787, 0x2A183025, 0x26436686, 0xD7C134AA},
   //Pre-computed value mu
   {0xB36F5F4F, 0xEF60DC4D, 0x33DA784F, 0x603DE8FD, 0x4E1D543F, 0x8FD22299, 0x2FC099F7, 0x00000001},
   //Curve parameter a
   {0xCAD29F43, 0xB0042A59, 0x4E182AD8, 0xC1530B51, 0x299803A6, 0xA9CE6C1C, 0x68A5E62C},
   //Curve parameter b
   {0x386C400B, 0x66DBB372, 0x3E2135D2, 0xA92369E3, 0x870713B1, 0xCFE44138, 0x2580F63C},
   //Base point G
   {
      //x-coordinate
      {0xEE12C07D, 0x4C1E6EFD, 0x9E4CE317, 0xA87DC68C, 0x340823B2, 0x2C7E5CF4, 0x0D9029AD},
      //y-coordinate
      {0x761402CD, 0xCAA3F6D3, 0x354B9E99, 0x4ECDAC24, 0x24C6B89E, 0x72C0726F, 0x58AA56F7},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xA5A7939F, 0x6DDEBCA3, 0xD116BC4B, 0x75D0FB98, 0x2A183025, 0x26436686, 0xD7C134AA},
   //Pre-computed value mu
   {0x1C8A5BA1, 0x590A94D3, 0xBEE15BC3, 0x603F1E9F, 0x4E1D543F, 0x8FD22299, 0x2FC099F7, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP224r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP224r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP224T1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP224t1 elliptic curve
 **/

const EcCurve brainpoolP224t1Curve =
{
   //Curve name
   "brainpoolP224t1",
   //Object identifier
   BRAINPOOLP224T1_OID,
   sizeof(BRAINPOOLP224T1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   224,
   //Order size, in bits
   224,
   //Prime modulus p
   {0x7EC8C0FF, 0x97DA89F5, 0xB09F0757, 0x75D1D787, 0x2A183025, 0x26436686, 0xD7C134AA},
   //Pre-computed value mu
   {0xB36F5F4F, 0xEF60DC4D, 0x33DA784F, 0x603DE8FD, 0x4E1D543F, 0x8FD22299, 0x2FC099F7, 0x00000001},
   //Curve parameter a
   {0x7EC8C0FC, 0x97DA89F5, 0xB09F0757, 0x75D1D787, 0x2A183025, 0x26436686, 0xD7C134AA},
   //Curve parameter b
   {0x8A60888D, 0xB3BB64F1, 0x0DA14C08, 0x0CED1ED2, 0xEF271BF6, 0x4104CD7B, 0x4B337D93},
   //Base point G
   {
      //x-coordinate
      {0x29B4D580, 0x8AC0C760, 0xCB49F892, 0xFE14762E, 0x96424E7F, 0xCE25FF38, 0x6AB1E344},
      //y-coordinate
      {0x1A46DB4C, 0x1C6ABD5F, 0x41C8CC0D, 0x7C0D4B1E, 0xD23F3F4D, 0x143E568C, 0x0374E9F5},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xA5A7939F, 0x6DDEBCA3, 0xD116BC4B, 0x75D0FB98, 0x2A183025, 0x26436686, 0xD7C134AA},
   //Pre-computed value mu
   {0x1C8A5BA1, 0x590A94D3, 0xBEE15BC3, 0x603F1E9F, 0x4E1D543F, 0x8FD22299, 0x2FC099F7, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP224t1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP224t1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP256R1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP256r1 elliptic curve
 **/

const EcCurve brainpoolP256r1Curve =
{
   //Curve name
   "brainpoolP256r1",
   //Object identifier
   BRAINPOOLP256R1_OID,
   sizeof(BRAINPOOLP256R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   256,
   //Order size, in bits
   256,
   //Prime modulus p
   {0x1F6E5377, 0x2013481D, 0xD5262028, 0x6E3BF623, 0x9D838D72, 0x3E660A90, 0xA1EEA9BC, 0xA9FB57DB},
   //Pre-computed value mu
   {0x1180DD0C, 0xB62AE630, 0xFF6A2FA9, 0x9B4F54A0, 0x322A7BF2, 0xBB73ABA8, 0xA1C55B7E, 0x818C1131,
    0x00000001},
   //Curve parameter a
   {0xF330B5D9, 0xE94A4B44, 0x26DC5C6C, 0xFB8055C1, 0x417AFFE7, 0xEEF67530, 0xFC2C3057, 0x7D5A0975},
   //Curve parameter b
   {0xFF8C07B6, 0x6BCCDC18, 0x5CF7E1CE, 0x95841629, 0xBBD77CBF, 0xF330B5D9, 0xE94A4B44, 0x26DC5C6C},
   //Base point G
   {
      //x-coordinate
      {0x9ACE3262, 0x3A4453BD, 0xE3BD23C2, 0xB9DE27E1, 0xFC81B7AF, 0x2C4B482F, 0xCB7E57CB, 0x8BD2AEB9},
      //y-coordinate
      {0x2F046997, 0x5C1D54C7, 0x2DED8E54, 0xC2774513, 0x14611DC9, 0x97F8461A, 0xC3DAC4FD, 0x547EF835},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x974856A7, 0x901E0E82, 0xB561A6F7, 0x8C397AA3, 0x9D838D71, 0x3E660A90, 0xA1EEA9BC, 0xA9FB57DB},
   //Pre-computed value mu
   {0xCCD10716, 0x50D73B46, 0x5FDF55EA, 0x9BF0088C, 0x322A7BF4, 0xBB73ABA8, 0xA1C55B7E, 0x818C1131,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP256r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP256r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP256T1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP256t1 elliptic curve
 **/

const EcCurve brainpoolP256t1Curve =
{
   //Curve name
   "brainpoolP256t1",
   //Object identifier
   BRAINPOOLP256T1_OID,
   sizeof(BRAINPOOLP256T1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   256,
   //Order size, in bits
   256,
   //Prime modulus p
   {0x1F6E5377, 0x2013481D, 0xD5262028, 0x6E3BF623, 0x9D838D72, 0x3E660A90, 0xA1EEA9BC, 0xA9FB57DB},
   //Pre-computed value mu
   {0x1180DD0C, 0xB62AE630, 0xFF6A2FA9, 0x9B4F54A0, 0x322A7BF2, 0xBB73ABA8, 0xA1C55B7E, 0x818C1131,
    0x00000001},
   //Curve parameter a
   {0x1F6E5374, 0x2013481D, 0xD5262028, 0x6E3BF623, 0x9D838D72, 0x3E660A90, 0xA1EEA9BC, 0xA9FB57DB},
   //Curve parameter b
   {0xFEE92B04, 0x6AE58101, 0xAF2F4925, 0xBF93EBC4, 0x3D0B76B7, 0xFE66A773, 0x30D84EA4, 0x662C61C4},
   //Base point G
   {
      //x-coordinate
      {0x2E1305F4, 0x79A19156, 0x7AAFBC2B, 0xAFA142C4, 0x3A656149, 0x732213B2, 0xC1CFE7B7, 0xA3E8EB3C},
      //y-coordinate
      {0x5B25C9BE, 0x1DABE8F3, 0x39D02700, 0x69BCB6DE, 0x4644417E, 0x7F7B22E1, 0x3439C56D, 0x2D996C82},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x974856A7, 0x901E0E82, 0xB561A6F7, 0x8C397AA3, 0x9D838D71, 0x3E660A90, 0xA1EEA9BC, 0xA9FB57DB},
   //Pre-computed value mu
   {0xCCD10716, 0x50D73B46, 0x5FDF55EA, 0x9BF0088C, 0x322A7BF4, 0xBB73ABA8, 0xA1C55B7E, 0x818C1131,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP256t1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP256t1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP320R1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP320r1 elliptic curve
 **/

const EcCurve brainpoolP320r1Curve =
{
   //Curve name
   "brainpoolP320r1",
   //Object identifier
   BRAINPOOLP320R1_OID,
   sizeof(BRAINPOOLP320R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   320,
   //Order size, in bits
   320,
   //Prime modulus p
   {0xF1B32E27, 0xFCD412B1, 0x7893EC28, 0x4F92B9EC, 0xF6F40DEF, 0xF98FCFA6, 0xD201E065, 0xE13C785E,
    0x36BC4FB7, 0xD35E4720},
   //Pre-computed value mu
   {0xDDC4B621, 0x2D8C7CAF, 0x3D5AB45A, 0x55D42A20, 0x2237985C, 0x22B851A5, 0x89AD9837, 0x4195C155,
    0xAF1AA120, 0x360E55A5, 0x00000001},
   //Curve parameter a
   {0x7D860EB4, 0x92F375A9, 0x85FFA9F4, 0x66190EB0, 0xF5EB79DA, 0xA2A73513, 0x6D3F3BB8, 0x83CCEBD4,
    0x8FBAB0F8, 0x3EE30B56},
   //Curve parameter b
   {0x8FB1F1A6, 0x6F5EB4AC, 0x88453981, 0xCC31DCCD, 0x9554B49A, 0xE13F4134, 0x40688A6F, 0xD3AD1986,
    0x9DFDBC42, 0x52088394},
   //Base point G
   {
      //x-coordinate
      {0x39E20611, 0x10AF8D0D, 0x10A599C7, 0xE7871E2A, 0x0A087EB6, 0xF20137D1, 0x8EE5BFE6, 0x5289BCC4,
       0xFB53D8B8, 0x43BD7E9A},
      //y-coordinate
      {0x692E8EE1, 0xD35245D1, 0xAAAC6AC7, 0xA9C77877, 0x117182EA, 0x0743FFED, 0x7F77275E, 0xAB409324,
       0x45EC1CC8, 0x14FDD055},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x44C59311, 0x8691555B, 0xEE8658E9, 0x2D482EC7, 0xB68F12A3, 0xF98FCFA5, 0xD201E065, 0xE13C785E,
    0x36BC4FB7, 0xD35E4720},
   //Pre-computed value mu
   {0xAFA14203, 0x059081EA, 0xA154E856, 0x80461C1B, 0xF8341FE6, 0x22B851A6, 0x89AD9837, 0x4195C155,
    0xAF1AA120, 0x360E55A5, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP320r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP320r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP320T1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP320t1 elliptic curve
 **/

const EcCurve brainpoolP320t1Curve =
{
   //Curve name
   "brainpoolP320t1",
   //Object identifier
   BRAINPOOLP320T1_OID,
   sizeof(BRAINPOOLP320T1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   320,
   //Order size, in bits
   320,
   //Prime modulus p
   {0xF1B32E27, 0xFCD412B1, 0x7893EC28, 0x4F92B9EC, 0xF6F40DEF, 0xF98FCFA6, 0xD201E065, 0xE13C785E,
    0x36BC4FB7, 0xD35E4720},
   //Pre-computed value mu
   {0xDDC4B621, 0x2D8C7CAF, 0x3D5AB45A, 0x55D42A20, 0x2237985C, 0x22B851A5, 0x89AD9837, 0x4195C155,
    0xAF1AA120, 0x360E55A5, 0x00000001},
   //Curve parameter a
   {0xF1B32E24, 0xFCD412B1, 0x7893EC28, 0x4F92B9EC, 0xF6F40DEF, 0xF98FCFA6, 0xD201E065, 0xE13C785E,
    0x36BC4FB7, 0xD35E4720},
   //Curve parameter b
   {0x22340353, 0xB5B4FEF4, 0xB8A547CE, 0x80AAF77F, 0x7ED27C67, 0x064C19F2, 0xDB782013, 0x60B3D147,
    0x38EB1ED5, 0xA7F561E0},
   //Base point G
   {
      //x-coordinate
      {0xA21BED52, 0x3357F624, 0xCC136FFF, 0x7EE07868, 0x6C4F09CB, 0x3408AB10, 0x90010F81, 0x4D3E7D49,
       0x01AFC6FB, 0x925BE9FB},
      //y-coordinate
      {0x5FB0D2C3, 0x1B9BC045, 0x9D1EE71B, 0x42A5A098, 0xA0B077AD, 0xEE084E58, 0x7ABB30EB, 0x6671DBEF,
       0x27483EBF, 0x63BA3A7A},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x44C59311, 0x8691555B, 0xEE8658E9, 0x2D482EC7, 0xB68F12A3, 0xF98FCFA5, 0xD201E065, 0xE13C785E,
    0x36BC4FB7, 0xD35E4720},
   //Pre-computed value mu
   {0xAFA14203, 0x059081EA, 0xA154E856, 0x80461C1B, 0xF8341FE6, 0x22B851A6, 0x89AD9837, 0x4195C155,
    0xAF1AA120, 0x360E55A5, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP320t1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP320t1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP384R1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP384r1 elliptic curve
 **/

const EcCurve brainpoolP384r1Curve =
{
   //Curve name
   "brainpoolP384r1",
   //Object identifier
   BRAINPOOLP384R1_OID,
   sizeof(BRAINPOOLP384R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   384,
   //Order size, in bits
   384,
   //Prime modulus p
   {0x3107EC53, 0x87470013, 0x901D1A71, 0xACD3A729, 0x7FB71123, 0x12B1DA19, 0xED5456B4, 0x152F7109,
    0x50E641DF, 0x0F5D6F7E, 0xA3386D28, 0x8CB91E82},
   //Pre-computed value mu
   {0x84A26716, 0x10A03BF6, 0x7A71566F, 0x9047BCE0, 0xF1C4D721, 0x9ED590CE, 0xCAE56EDE, 0xDDA2C449,
    0x3CC6FA65, 0xFF25ADFD, 0x6D8EC6B8, 0xD1B575B1, 0x00000001},
   //Curve parameter a
   {0x22CE2826, 0x04A8C7DD, 0x503AD4EB, 0x8AA5814A, 0xBA91F90F, 0x139165EF, 0x4FB22787, 0xC2BEA28E,
    0xCE05AFA0, 0x3C72080A, 0x3D8C150C, 0x7BC382C6},
   //Curve parameter b
   {0xFA504C11, 0x3AB78696, 0x95DBC994, 0x7CB43902, 0x3EEB62D5, 0x2E880EA5, 0x07DCD2A6, 0x2FB77DE1,
    0x16F0447C, 0x8B39B554, 0x22CE2826, 0x04A8C7DD},
   //Base point G
   {
      //x-coordinate
      {0x47D4AF1E, 0xEF87B2E2, 0x36D646AA, 0xE826E034, 0x0CBD10E8, 0xDB7FCAFE, 0x7EF14FE3, 0x8847A3E7,
       0xB7C13F6B, 0xA2A63A81, 0x68CF45FF, 0x1D1C64F0},
      //y-coordinate
      {0x263C5315, 0x42820341, 0x77918111, 0x0E464621, 0xF9912928, 0xE19C054F, 0xFEEC5864, 0x62B70B29,
       0x95CFD552, 0x5CB1EB8E, 0x20F9C2A4, 0x8ABE1D75},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xE9046565, 0x3B883202, 0x6B7FC310, 0xCF3AB6AF, 0xAC0425A7, 0x1F166E6C, 0xED5456B3, 0x152F7109,
    0x50E641DF, 0x0F5D6F7E, 0xA3386D28, 0x8CB91E82},
   //Pre-computed value mu
   {0xF8A71F8A, 0x600ADCCC, 0x7A652109, 0x189FDB46, 0x165031E7, 0xC506F2FE, 0xCAE56EE1, 0xDDA2C449,
    0x3CC6FA65, 0xFF25ADFD, 0x6D8EC6B8, 0xD1B575B1, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP384r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP384r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP384T1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP384t1 elliptic curve
 **/

const EcCurve brainpoolP384t1Curve =
{
   //Curve name
   "brainpoolP384t1",
   //Object identifier
   BRAINPOOLP384T1_OID,
   sizeof(BRAINPOOLP384T1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   384,
   //Order size, in bits
   384,
   //Prime modulus p
   {0x3107EC53, 0x87470013, 0x901D1A71, 0xACD3A729, 0x7FB71123, 0x12B1DA19, 0xED5456B4, 0x152F7109,
    0x50E641DF, 0x0F5D6F7E, 0xA3386D28, 0x8CB91E82},
   //Pre-computed value mu
   {0x84A26716, 0x10A03BF6, 0x7A71566F, 0x9047BCE0, 0xF1C4D721, 0x9ED590CE, 0xCAE56EDE, 0xDDA2C449,
    0x3CC6FA65, 0xFF25ADFD, 0x6D8EC6B8, 0xD1B575B1, 0x00000001},
   //Curve parameter a
   {0x3107EC50, 0x87470013, 0x901D1A71, 0xACD3A729, 0x7FB71123, 0x12B1DA19, 0xED5456B4, 0x152F7109,
    0x50E641DF, 0x0F5D6F7E, 0xA3386D28, 0x8CB91E82},
   //Curve parameter b
   {0x33B471EE, 0xED70355A, 0x3B88805C, 0x2074AA26, 0x756DCE1D, 0x4B1ABD11, 0x8CCDC64E, 0x4B9346ED,
    0x47910F8C, 0xD826DBA6, 0xA7BDA81B, 0x7F519EAD},
   //Base point G
   {
      //x-coordinate
      {0x418808CC, 0xD8D0AA2F, 0x946A5F54, 0xC4FF191B, 0x462AABFF, 0x2476FECD, 0xEBD65317, 0x9B80AB12,
       0x35F72A81, 0xF2AFCD72, 0x2DB9A306, 0x18DE98B0},
      //y-coordinate
      {0x9E582928, 0x2675BF5B, 0x4DC2B291, 0x46940858, 0xA208CCFE, 0x3B88F2B6, 0x5B7A1FCA, 0x747F9347,
       0x755AD336, 0xA114AFD2, 0x62D30651, 0x25AB0569},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xE9046565, 0x3B883202, 0x6B7FC310, 0xCF3AB6AF, 0xAC0425A7, 0x1F166E6C, 0xED5456B3, 0x152F7109,
    0x50E641DF, 0x0F5D6F7E, 0xA3386D28, 0x8CB91E82},
   //Pre-computed value mu
   {0xF8A71F8A, 0x600ADCCC, 0x7A652109, 0x189FDB46, 0x165031E7, 0xC506F2FE, 0xCAE56EE1, 0xDDA2C449,
    0x3CC6FA65, 0xFF25ADFD, 0x6D8EC6B8, 0xD1B575B1, 0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP384t1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP384t1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP512R1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP512r1 elliptic curve
 **/

const EcCurve brainpoolP512r1Curve =
{
   //Curve name
   "brainpoolP512r1",
   //Object identifier
   BRAINPOOLP512R1_OID,
   sizeof(BRAINPOOLP512R1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS,
   //Field size, in bits
   512,
   //Order size, in bits
   512,
   //Prime modulus p
   {0x583A48F3, 0x28AA6056, 0x2D82C685, 0x2881FF2F, 0xE6A380E6, 0xAECDA12A, 0x9BC66842, 0x7D4D9B00,
    0x70330871, 0xD6639CCA, 0xB3C9D20E, 0xCB308DB3, 0x33C9FC07, 0x3FD4E6AE, 0xDBE9C48B, 0xAADD9DB8},
   //Pre-computed value mu
   {0xE911E8D9, 0x17E2CF84, 0x603556D1, 0x71D621C4, 0x4E73EA8C, 0xE47D9303, 0x823152C5, 0x42FF2B38,
    0xF5BF92F5, 0x666AD8F2, 0xCC44EF09, 0x8373AF60, 0x03461E1E, 0x15D5EA2F, 0xD6DAEB8A, 0x7F8D7F4E,
    0x00000001},
   //Curve parameter a
   {0x77FC94CA, 0xE7C1AC4D, 0x2BF2C7B9, 0x7F1117A7, 0x8B9AC8B5, 0x0A2EF1C9, 0xA8253AA1, 0x2DED5D5A,
    0xEA9863BC, 0xA83441CA, 0x3DF91610, 0x94CBDD8D, 0xAC234CC5, 0xE2327145, 0x8B603B89, 0x7830A331},
   //Curve parameter b
   {0x8016F723, 0x2809BD63, 0x5EBAE5DD, 0x984050B7, 0xDC083E67, 0x77FC94CA, 0xE7C1AC4D, 0x2BF2C7B9,
    0x7F1117A7, 0x8B9AC8B5, 0x0A2EF1C9, 0xA8253AA1, 0x2DED5D5A, 0xEA9863BC, 0xA83441CA, 0x3DF91610},
   //Base point G
   {
      //x-coordinate
      {0xBCB9F822, 0x8B352209, 0x406A5E68, 0x7C6D5047, 0x93B97D5F, 0x50D1687B, 0xE2D0D48D, 0xFF3B1F78,
       0xF4D0098E, 0xB43B62EE, 0xB5D916C1, 0x85ED9F70, 0x9C4C6A93, 0x5A21322E, 0xD82ED964, 0x81AEE4BD},
      //y-coordinate
      {0x3AD80892, 0x78CD1E0F, 0xA8F05406, 0xD1CA2B2F, 0x8A2763AE, 0x5BCA4BD8, 0x4A5F485E, 0xB2DCDE49,
       0x881F8111, 0xA000C55B, 0x24A57B1A, 0xF209F700, 0xCF7822FD, 0xC0EABFA9, 0x566332EC, 0x7DDE385D},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x9CA90069, 0xB5879682, 0x085DDADD, 0x1DB1D381, 0x7FAC1047, 0x41866119, 0x4CA92619, 0x553E5C41,
    0x70330870, 0xD6639CCA, 0xB3C9D20E, 0xCB308DB3, 0x33C9FC07, 0x3FD4E6AE, 0xDBE9C48B, 0xAADD9DB8},
   //Pre-computed value mu
   {0xDB57DB37, 0x2FAFAC64, 0x15D5C4CE, 0x0EAF0D90, 0x59EE4710, 0x9FF38F5F, 0x1A235D44, 0xDB9470C6,
    0xF5BF92F7, 0x666AD8F2, 0xCC44EF09, 0x8373AF60, 0x03461E1E, 0x15D5EA2F, 0xD6DAEB8A, 0x7F8D7F4E,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP512r1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP512r1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (BRAINPOOLP512T1_SUPPORT == ENABLED)

/**
 * @brief brainpoolP512t1 elliptic curve
 **/

const EcCurve brainpoolP512t1Curve =
{
   //Curve name
   "brainpoolP512t1",
   //Object identifier
   BRAINPOOLP512T1_OID,
   sizeof(BRAINPOOLP512T1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   512,
   //Order size, in bits
   512,
   //Prime modulus p
   {0x583A48F3, 0x28AA6056, 0x2D82C685, 0x2881FF2F, 0xE6A380E6, 0xAECDA12A, 0x9BC66842, 0x7D4D9B00,
    0x70330871, 0xD6639CCA, 0xB3C9D20E, 0xCB308DB3, 0x33C9FC07, 0x3FD4E6AE, 0xDBE9C48B, 0xAADD9DB8},
   //Pre-computed value mu
   {0xE911E8D9, 0x17E2CF84, 0x603556D1, 0x71D621C4, 0x4E73EA8C, 0xE47D9303, 0x823152C5, 0x42FF2B38,
    0xF5BF92F5, 0x666AD8F2, 0xCC44EF09, 0x8373AF60, 0x03461E1E, 0x15D5EA2F, 0xD6DAEB8A, 0x7F8D7F4E,
    0x00000001},
   //Curve parameter a
   {0x583A48F0, 0x28AA6056, 0x2D82C685, 0x2881FF2F, 0xE6A380E6, 0xAECDA12A, 0x9BC66842, 0x7D4D9B00,
    0x70330871, 0xD6639CCA, 0xB3C9D20E, 0xCB308DB3, 0x33C9FC07, 0x3FD4E6AE, 0xDBE9C48B, 0xAADD9DB8},
   //Curve parameter b
   {0x1867423E, 0x180EA257, 0x65763689, 0xC22553B4, 0xF2DAE145, 0xF6450085, 0x04976540, 0x2BCDFA23,
    0xEC3E36A6, 0x7897504B, 0xCB498152, 0x21F70C0B, 0x6884EAE3, 0x6E1890E4, 0x441CFAB7, 0x7CBBBCF9},
   //Base point G
   {
      //x-coordinate
      {0xFA9035DA, 0x1BAA2696, 0xE26F06B5, 0xF7A3F25F, 0xD6943A64, 0x99AA77A7, 0x5CDB3EA4, 0x82BA5173,
       0x39C0313D, 0x9DB1758D, 0x58C56DDE, 0xBA858424, 0xCBC2A6FE, 0xB9C1BA06, 0x12788717, 0x640ECE5C},
      //y-coordinate
      {0x00F8B332, 0xE198B61E, 0x6DBB8BAC, 0x306ECFF9, 0xDF86A627, 0xD71DF2DA, 0xBEEF216B, 0xD9932184,
       0xAE03CEE9, 0x1131159C, 0xB71634C0, 0xBB4E3019, 0x6C84ACE1, 0xA2C89237, 0x95F5AF0F, 0x5B534BD5},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x9CA90069, 0xB5879682, 0x085DDADD, 0x1DB1D381, 0x7FAC1047, 0x41866119, 0x4CA92619, 0x553E5C41,
    0x70330870, 0xD6639CCA, 0xB3C9D20E, 0xCB308DB3, 0x33C9FC07, 0x3FD4E6AE, 0xDBE9C48B, 0xAADD9DB8},
   //Pre-computed value mu
   {0xDB57DB37, 0x2FAFAC64, 0x15D5C4CE, 0x0EAF0D90, 0x59EE4710, 0x9FF38F5F, 0x1A235D44, 0xDB9470C6,
    0xF5BF92F7, 0x666AD8F2, 0xCC44EF09, 0x8373AF60, 0x03461E1E, 0x15D5EA2F, 0xD6DAEB8A, 0x7F8D7F4E,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   brainpoolP512t1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   brainpoolP512t1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (FRP256V1_SUPPORT == ENABLED)

/**
 * @brief FRP256v1 elliptic curve
 **/

const EcCurve frp256v1Curve =
{
   //Curve name
   "FRP256v1",
   //Object identifier
   FRP256V1_OID,
   sizeof(FRP256V1_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   256,
   //Order size, in bits
   256,
   //Prime modulus p
   {0xD86E9C03, 0xE8FCF353, 0xABC8CA6D, 0x3961ADBC, 0xCE42435B, 0x10126DE8, 0x0B3AD58F, 0xF1FD178C},
   //Pre-computed value mu
   {0x9002424F, 0x6ABA3ABF, 0xC20522AE, 0x07B58508, 0x8851C193, 0xF36AF7F5, 0xC7D2B040, 0x0ED297DC,
    0x00000001},
   //Curve parameter a
   {0xD86E9C00, 0xE8FCF353, 0xABC8CA6D, 0x3961ADBC, 0xCE42435B, 0x10126DE8, 0x0B3AD58F, 0xF1FD178C},
   //Curve parameter b
   {0x7B7BB73F, 0x3075ED96, 0xE4B1A180, 0xDFEC0C9A, 0x4A44C00F, 0x0D4ABA75, 0x5428A930, 0xEE353FCA},
   //Base point G
   {
      //x-coordinate
      {0xD98F5CFF, 0x64C97A2D, 0xAF98B701, 0x8C27D2DC, 0x49D42395, 0x31183D47, 0x56C139EB, 0xB6B3D4C3},
      //y-coordinate
      {0x54062CFB, 0x83115A15, 0xE8E4C9E1, 0x2701C307, 0xF3ECEF8C, 0x1F9271F0, 0xC8B20491, 0x6142E0F7},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xC6D655E1, 0x1FFDD459, 0x40D2BF94, 0x53DC67E1, 0xCE42435B, 0x10126DE8, 0x0B3AD58F, 0xF1FD178C},
   //Pre-computed value mu
   {0xE02F4C13, 0xC7CFD1DA, 0xCEAD1E3F, 0xEA1313F7, 0x8851C192, 0xF36AF7F5, 0xC7D2B040, 0x0ED297DC,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   frp256v1FieldMod,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   frp256v1ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SM2_SUPPORT == ENABLED)

/**
 * @brief SM2 elliptic curve
 **/

const EcCurve sm2Curve =
{
   //Curve name
   "curveSM2",
   //Object identifier
   SM2_OID,
   sizeof(SM2_OID),
   //Curve type
   EC_CURVE_TYPE_WEIERSTRASS_A3,
   //Field size, in bits
   256,
   //Order size, in bits
   256,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFFC, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE},
   //Curve parameter b
   {0x4D940E93, 0xDDBCBD41, 0x15AB8F92, 0xF39789F5, 0xCF6509A7, 0x4D5A9E4B, 0x9D9F5E34, 0x28E9FA9E},
   //Base point G
   {
      //x-coordinate
      {0x334C74C7, 0x715A4589, 0xF2660BE1, 0x8FE30BBF, 0x6A39C994, 0x5F990446, 0x1F198119, 0x32C4AE2C},
      //y-coordinate
      {0x2139F0A0, 0x02DF32E5, 0xC62A4740, 0xD0A9877C, 0x6B692153, 0x59BDCEE3, 0xF4F6779C, 0xBC3736A2},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x39D54123, 0x53BBF409, 0x21C6052B, 0x7203DF6B, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE},
   //Pre-computed value mu
   {0xF15149A0, 0x12AC6361, 0xFA323C01, 0x8DFC2096, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
    0x00000001},
   //Cofactor
   1,
   //Field modular reduction
   sm2FieldMod,
   //Field modular inversion
   sm2FieldInv,
   //Scalar modular reduction
   sm2ScalarMod,
   //Scalar modular inversion
   NULL,
};

#endif
#if (X25519_SUPPORT == ENABLED)

/**
 * @brief Curve25519 elliptic curve
 **/

const EcCurve x25519Curve =
{
   //Curve name
   "curve25519",
   //Object identifier
   X25519_OID,
   sizeof(X25519_OID),
   //Curve type
   EC_CURVE_TYPE_MONTGOMERY,
   //Field size, in bits
   255,
   //Order size, in bits
   253,
   //Prime modulus p
   {0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x00076D06},
   //Curve parameter b
   {0x00000001},
   //Base point G
   {
      //x-coordinate
      {0x00000009},
      //y-coordinate
      {0x7ECED3D9, 0x29E9C5A2, 0x6D7C61B2, 0x923D4D7E, 0x7748D14C, 0xE01EDD2C, 0xB8A086B4, 0x20AE19A1},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000, 0x00000000, 0x10000000},
   //Pre-computed value mu
   {0},
   //Cofactor
   8,
   //Field modular reduction
   NULL,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   NULL,
   //Scalar modular inversion
   NULL,
};

#endif
#if (X448_SUPPORT == ENABLED)

/**
 * @brief Curve448 elliptic curve
 **/

const EcCurve x448Curve =
{
   //Curve name
   "curve448",
   //Object identifier
   X448_OID,
   sizeof(X448_OID),
   //Curve type
   EC_CURVE_TYPE_MONTGOMERY,
   //Field size, in bits
   448,
   //Order size, in bits
   446,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x000262A6},
   //Curve parameter b
   {0x00000001},
   //Base point G
   {
      //x-coordinate
      {0x00000005},
      //y-coordinate
      {0x457B5B1A, 0x6FD7223D, 0x50677AF7, 0x1312C4B1, 0x46430D21, 0xB8027E23, 0x8DF3F6ED, 0x60F75DC2,
       0xF55545D0, 0xCBAE5D34, 0x58326FCE, 0x6C98AB6E, 0x95F5B1F6, 0x7D235D12},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xAB5844F3, 0x2378C292, 0x8DC58F55, 0x216CC272, 0xAED63690, 0xC44EDB49, 0x7CCA23E9, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF},
   //Pre-computed value mu
   {0},
   //Cofactor
   4,
   //Field modular reduction
   NULL,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   NULL,
   //Scalar modular inversion
   NULL,
};

#endif
#if (ED25519_SUPPORT == ENABLED)

/**
 * @brief Ed25519 elliptic curve
 **/

const EcCurve ed25519Curve =
{
   //Curve name
   "Ed25519",
   //Object identifier
   ED25519_OID,
   sizeof(ED25519_OID),
   //Curve type
   EC_CURVE_TYPE_EDWARDS,
   //Field size, in bits
   255,
   //Order size, in bits
   253,
   //Prime modulus p
   {0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0xFFFFFFEC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF},
   //Curve parameter d
   {0x135978A3, 0x75EB4DCA, 0x4141D8AB, 0x00700A4D, 0x7779E898, 0x8CC74079, 0x2B6FFE73, 0x52036CEE},
   //Base point G
   {
      //x-coordinate
      {0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760, 0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE, 0x216936D3},
      //y-coordinate
      {0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000, 0x00000000, 0x10000000},
   //Pre-computed value mu
   {0},
   //Cofactor
   8,
   //Field modular reduction
   NULL,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   NULL,
   //Scalar modular inversion
   NULL,
};

#endif
#if (ED448_SUPPORT == ENABLED)

/**
 * @brief Ed448 elliptic curve
 **/

const EcCurve ed448Curve =
{
   //Curve name
   "Ed448",
   //Object identifier
   ED448_OID,
   sizeof(ED448_OID),
   //Curve type
   EC_CURVE_TYPE_EDWARDS,
   //Field size, in bits
   448,
   //Order size, in bits
   446,
   //Prime modulus p
   {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
   //Pre-computed value mu
   {0},
   //Curve parameter a
   {0x0000001},
   //Curve parameter d
   {0xBAA156B9, 0x243CC32D, 0x58FB61C4, 0xD0809970, 0x264CFE9A, 0x9CCC9C81, 0x412A12E7, 0x809B1DA3,
    0x42A50F37, 0xAD461572, 0x9373A2CC, 0xF24F38C2, 0x7F0DAF19, 0xD78B4BDC},
   //Base point G
   {
      //x-coordinate
      {0x3E9C04FC, 0x69871309, 0x8496CD11, 0x9DE732F3, 0xED697224, 0xE21F7787, 0x728BDC93, 0x0C25A07D,
       0xC9296924, 0x1128751A, 0x16C792C6, 0xAE7C9DF4, 0x70400553, 0x79A70B2B},
      //y-coordinate
      {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0xFFFFFFFF,
       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF},
      //z-coordinate
      {0x00000001}
   },
   //Base point order q
   {0xAB5844F3, 0x2378C292, 0x8DC58F55, 0x216CC272, 0xAED63690, 0xC44EDB49, 0x7CCA23E9, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF},
   //Pre-computed value mu
   {0},
   //Cofactor
   4,
   //Field modular reduction
   NULL,
   //Field modular inversion
   NULL,
   //Scalar modular reduction
   NULL,
   //Scalar modular inversion
   NULL,
};

#endif
#if (SECP112R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp112r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp112r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint64_t temp;
   uint32_t u[4];
   uint32_t v[4];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   temp = (uint64_t) a[3] * 76439;
   temp >>= 32;
   temp += (uint64_t) a[4] * 76439;
   u[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[5] * 76439;
   u[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[6] * 76439;
   u[2] = (uint32_t) temp;
   temp >>= 32;
   u[3] = (uint32_t) temp;

   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 4);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 4);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 4);
   ecScalarSelect(u, v, u, c, 4);
   c = ecScalarSub(v, u, curve->p, 4);
   ecScalarSelect(r, v, u, c, 4);
}


/**
 * @brief Scalar modular reduction (secp112r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp112r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[4];
   uint32_t v[4];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 3, curve->qmu, 4);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 4);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 4);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 4);
   ecScalarSelect(u, v, u, c, 4);
   c = ecScalarSub(v, u, curve->q, 4);
   ecScalarSelect(r, v, u, c, 4);
}

#endif
#if (SECP112R2_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp112r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp112r2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint64_t temp;
   uint32_t u[4];
   uint32_t v[4];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   temp = (uint64_t) a[3] * 76439;
   temp >>= 32;
   temp += (uint64_t) a[4] * 76439;
   u[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[5] * 76439;
   u[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[6] * 76439;
   u[2] = (uint32_t) temp;
   temp >>= 32;
   u[3] = (uint32_t) temp;

   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 4);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 4);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 4);
   ecScalarSelect(u, v, u, c, 4);
   c = ecScalarSub(v, u, curve->p, 4);
   ecScalarSelect(r, v, u, c, 4);
}


/**
 * @brief Scalar modular reduction (secp112r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp112r2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t a2[7];
   uint32_t q2[4];
   uint32_t u[4];
   uint32_t v[4];

   //Compute a = a << 2
   ecScalarShiftLeft(a2, a, 2, 7);
   //Compute q = q << 2
   ecScalarShiftLeft(q2, curve->q, 2, 4);

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a2 + 3, curve->qmu, 4);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, q2, 4);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a2, v, 4);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, q2, 4);
   ecScalarSelect(u, v, u, c, 4);
   c = ecScalarSub(v, u, q2, 4);
   ecScalarSelect(u, v, u, c, 4);

   //Compute a = u >> 2
   ecScalarShiftRight(r, u, 2, 4);
}

#endif
#if (SECP128R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp128r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp128r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0] + a[4] + a[5] + a[5];
   temp += (uint64_t) a[6] << 2;
   temp += (uint64_t) a[7] << 3;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[5] + a[6] + a[6];
   temp += (uint64_t) a[7] << 2;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[6] + a[7] + a[7];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[4] + a[4] + a[7];
   temp += (uint64_t) a[5] << 2;
   temp += (uint64_t) a[6] << 3;
   temp += (uint64_t) a[7] << 4;
   r[3] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3] + c + c;
   r[3] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3] + c + c;
   r[3] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp128r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp128r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[4];
   uint32_t v[4];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, v, u, 15);
   ecFieldMulMod(curve, v, u, v); //A^(2^30 - 1)
   ecFieldPwr2Mod(curve, u, v, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^61 - 2^30 - 1)
   ecFieldPwr2Mod(curve, u, u, 30);
   ecFieldMulMod(curve, u, u, v); //A^(2^91 - 2^60 - 1)
   ecFieldPwr2Mod(curve, u, u, 30);
   ecFieldMulMod(curve, u, u, v); //A^(2^121 - 2^90 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^122 - 2^91 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^123 - 2^92 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^124 - 2^93 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^125 - 2^94 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^126 - 2^95 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^128 - 2^97 - 3)
}


/**
 * @brief Scalar modular reduction (secp128r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp128r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->qmu, 9);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(r, v, u, c, 8);
}

#endif
#if (SECP128R2_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp128r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp128r2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0] + a[4] + a[5] + a[5];
   temp += (uint64_t) a[6] << 2;
   temp += (uint64_t) a[7] << 3;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[5] + a[6] + a[6];
   temp += (uint64_t) a[7] << 2;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[6] + a[7] + a[7];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[4] + a[4] + a[7];
   temp += (uint64_t) a[5] << 2;
   temp += (uint64_t) a[6] << 3;
   temp += (uint64_t) a[7] << 4;
   r[3] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3] + c + c;
   r[3] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3] + c + c;
   r[3] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp128r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp128r2FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[4];
   uint32_t v[4];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, v, u, 15);
   ecFieldMulMod(curve, v, u, v); //A^(2^30 - 1)
   ecFieldPwr2Mod(curve, u, v, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^61 - 2^30 - 1)
   ecFieldPwr2Mod(curve, u, u, 30);
   ecFieldMulMod(curve, u, u, v); //A^(2^91 - 2^60 - 1)
   ecFieldPwr2Mod(curve, u, u, 30);
   ecFieldMulMod(curve, u, u, v); //A^(2^121 - 2^90 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^122 - 2^91 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^123 - 2^92 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^124 - 2^93 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^125 - 2^94 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^126 - 2^95 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^128 - 2^97 - 3)
}


/**
 * @brief Scalar modular reduction (secp128r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp128r2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t a2[9];
   uint32_t q2[5];
   uint32_t u[5];
   uint32_t v[5];

   //Compute a = a << 2
   ecScalarShiftLeft(a2, a, 2, 9);
   //Compute q = q << 2
   ecScalarShiftLeft(q2, curve->q, 2, 5);

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a2 + 4, curve->qmu, 5);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, q2, 5);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a2, v, 5);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, q2, 5);
   ecScalarSelect(u, v, u, c, 5);
   c = ecScalarSub(v, u, q2, 5);
   ecScalarSelect(u, v, u, c, 5);

   //Compute a = u >> 2
   ecScalarShiftRight(r, u, 2, 5);
}

#endif
#if (SECP160K1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp160k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp160k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0];
   temp += (uint64_t) a[5] * 21389;
   temp += (uint64_t) a[9] * 21389;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[5] + a[9];
   temp += (uint64_t) a[6] * 21389;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[6];
   temp += (uint64_t) a[7] * 21389;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[7];
   temp += (uint64_t) a[8] * 21389;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4] + a[8];
   temp += (uint64_t) a[9] * 21389;
   r[4] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c * 21389;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c * 21389;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp160k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp160k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[5];
   uint32_t v[5];
   uint32_t w[5];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, w, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, u, w, 15);
   ecFieldMulMod(curve, u, u, w); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^31 - 1)
   ecFieldPwr2Mod(curve, v, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^62 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^63 - 1)
   ecFieldPwr2Mod(curve, v, u, 63);
   ecFieldMulMod(curve, u, u, v); //A^(2^126 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^127 - 1)
   ecFieldPwr2Mod(curve, u, u, 16);
   ecFieldMulMod(curve, u, u, w); //A^(2^143 - 2^15 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^144 - 2^16 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^145 - 2^17 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^147 - 2^19 - 2^1 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^149 - 2^21 - 2^3 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^150 - 2^22 - 2^4 - 2^2 - 1)
   ecFieldPwr2Mod(curve, u, u, 4);
   ecFieldMulMod(curve, u, u, a); //A^(2^154 - 2^26 - 2^8 - 2^6 - 2^3 - 2^2 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^155 - 2^27 - 2^9 - 2^7 - 2^4 - 2^3 - 2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^156 - 2^28 - 2^10 - 2^8 - 2^5 - 2^4 - 2^3 - 1)
   ecFieldPwr2Mod(curve, u, u, 4);
   ecFieldMulMod(curve, r, u, a); //A^(2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 3)
}


/**
 * @brief Scalar modular reduction (secp160k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp160k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t a2[11];
   uint32_t q2[6];
   uint32_t u[6];
   uint32_t v[6];

   //Compute a = a << 15
   ecScalarShiftLeft(a2, a, 15, 11);
   //Compute q = q << 15
   ecScalarShiftLeft(q2, curve->q, 15, 6);

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a2 + 5, curve->qmu, 6);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, q2, 6);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a2, v, 6);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, q2, 6);
   ecScalarSelect(u, v, u, c, 6);
   c = ecScalarSub(v, u, q2, 6);
   ecScalarSelect(u, v, u, c, 6);

   //Compute a = u >> 15
   ecScalarShiftRight(r, u, 15, 6);
}

#endif
#if (SECP160R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp160r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp160r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0] + a[5];
   temp += (uint64_t) a[5] << 31;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[6];
   temp += (uint64_t) a[6] << 31;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[7];
   temp += (uint64_t) a[7] << 31;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[8];
   temp += (uint64_t) a[8] << 31;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4] + a[9];
   temp += (uint64_t) a[9] << 31;
   r[4] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c + (c << 31);
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c + (c << 31);
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp160r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp160r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[5];
   uint32_t v[5];
   uint32_t w[5];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldPwr2Mod(curve, v, u, 14);
   ecFieldMulMod(curve, u, u, v); //A^(2^28 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, w, u, a); //A^(2^29 - 1)
   ecFieldSqrMod(curve, u, w);
   ecFieldMulMod(curve, u, u, a); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^31 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^32 - 1)
   ecFieldPwr2Mod(curve, v, u, 32);
   ecFieldMulMod(curve, u, u, v); //A^(2^64 - 1)
   ecFieldPwr2Mod(curve, v, u, 64);
   ecFieldMulMod(curve, u, u, v); //A^(2^128 - 1)
   ecFieldPwr2Mod(curve, u, u, 30);
   ecFieldMulMod(curve, u, u, w); //A^(2^158 - 2^29 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^160 - 2^31 - 3)
}


/**
 * @brief Scalar modular reduction (secp160r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp160r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t a2[11];
   uint32_t q2[6];
   uint32_t u[6];
   uint32_t v[6];

   //Compute a = a << 15
   ecScalarShiftLeft(a2, a, 15, 11);
   //Compute q = q << 15
   ecScalarShiftLeft(q2, curve->q, 15, 6);

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a2 + 5, curve->qmu, 6);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, q2, 6);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a2, v, 6);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, q2, 6);
   ecScalarSelect(u, v, u, c, 6);
   c = ecScalarSub(v, u, q2, 6);
   ecScalarSelect(u, v, u, c, 6);

   //Compute a = u >> 15
   ecScalarShiftRight(r, u, 15, 6);
}

#endif
#if (SECP160R2_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp160r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp160r2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0];
   temp += (uint64_t) a[5] * 21389;
   temp += (uint64_t) a[9] * 21389;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[5] + a[9];
   temp += (uint64_t) a[6] * 21389;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[6];
   temp += (uint64_t) a[7] * 21389;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[7];
   temp += (uint64_t) a[8] * 21389;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4] + a[8];
   temp += (uint64_t) a[9] * 21389;
   r[4] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c * 21389;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c * 21389;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp160r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp160r2FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[5];
   uint32_t v[5];
   uint32_t w[5];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, w, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, u, w, 15);
   ecFieldMulMod(curve, u, u, w); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^31 - 1)
   ecFieldPwr2Mod(curve, v, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^62 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^63 - 1)
   ecFieldPwr2Mod(curve, v, u, 63);
   ecFieldMulMod(curve, u, u, v); //A^(2^126 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^127 - 1)
   ecFieldPwr2Mod(curve, u, u, 16);
   ecFieldMulMod(curve, u, u, w); //A^(2^143 - 2^15 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^144 - 2^16 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^145 - 2^17 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^147 - 2^19 - 2^1 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^149 - 2^21 - 2^3 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^150 - 2^22 - 2^4 - 2^2 - 1)
   ecFieldPwr2Mod(curve, u, u, 4);
   ecFieldMulMod(curve, u, u, a); //A^(2^154 - 2^26 - 2^8 - 2^6 - 2^3 - 2^2 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^155 - 2^27 - 2^9 - 2^7 - 2^4 - 2^3 - 2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^156 - 2^28 - 2^10 - 2^8 - 2^5 - 2^4 - 2^3 - 1)
   ecFieldPwr2Mod(curve, u, u, 4);
   ecFieldMulMod(curve, r, u, a); //A^(2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 3)
}


/**
 * @brief Scalar modular reduction (secp160r2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp160r2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t a2[11];
   uint32_t q2[6];
   uint32_t u[6];
   uint32_t v[6];

   //Compute a = a << 15
   ecScalarShiftLeft(a2, a, 15, 11);
   //Compute q = q << 15
   ecScalarShiftLeft(q2, curve->q, 15, 6);

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a2 + 5, curve->qmu, 6);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, q2, 6);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a2, v, 6);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, q2, 6);
   ecScalarSelect(u, v, u, c, 6);
   c = ecScalarSub(v, u, q2, 6);
   ecScalarSelect(u, v, u, c, 6);

   //Compute a = u >> 15
   ecScalarShiftRight(r, u, 15, 6);
}

#endif
#if (SECP192K1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp192k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp192k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0];
   temp += (uint64_t) a[6] * 4553;
   temp += (uint64_t) a[11] * 4553;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[6] + a[11];
   temp += (uint64_t) a[7] * 4553;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[7];
   temp += (uint64_t) a[8] * 4553;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[8];
   temp += (uint64_t) a[9] * 4553;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4] + a[9];
   temp += (uint64_t) a[10] * 4553;
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[5] + a[10];
   temp += (uint64_t) a[11] * 4553;
   r[5] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c * 4553;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c * 4553;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp192k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp192k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[6];
   uint32_t v[6];
   uint32_t w[6];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldPwr2Mod(curve, v, u, 2);
   ecFieldMulMod(curve, u, u, v); //A^(2^4 - 1)
   ecFieldPwr2Mod(curve, v, u, 4);
   ecFieldMulMod(curve, u, u, v); //A^(2^8 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^9 - 1)
   ecFieldPwr2Mod(curve, v, u, 9);
   ecFieldMulMod(curve, u, u, v); //A^(2^18 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, w, u, a); //A^(2^19 - 1)
   ecFieldPwr2Mod(curve, u, w, 19);
   ecFieldMulMod(curve, u, u, w); //A^(2^38 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^39 - 1)
   ecFieldPwr2Mod(curve, v, u, 39);
   ecFieldMulMod(curve, u, u, v); //A^(2^78 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^79 - 1)
   ecFieldPwr2Mod(curve, v, u, 79);
   ecFieldMulMod(curve, u, u, v); //A^(2^158 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^159 - 1)
   ecFieldPwr2Mod(curve, u, u, 20);
   ecFieldMulMod(curve, u, u, w); //A^(2^179 - 2^19 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^181 - 2^21 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^182 - 2^22 - 2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^183 - 2^23 - 2^3 - 1)
   ecFieldPwr2Mod(curve, u, u, 4);
   ecFieldMulMod(curve, u, u, a); //A^(2^187 - 2^27 - 2^7 - 2^3 - 2^2 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^188 - 2^28 - 2^8 - 2^4 - 2^3 - 2^2 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^190 - 2^30 - 2^10 - 2^6 - 2^5 - 2^4 - 2^1 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 3)
}


/**
 * @brief Scalar modular reduction (secp192k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp192k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[7];
   uint32_t v[7];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 5, curve->qmu, 7);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 7);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 7);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(u, v, u, c, 7);
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(r, v, u, c, 6);
}

#endif
#if (SECP192R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp192r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp192r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0] + a[6] + a[10];
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[7] + a[11];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[6] + a[8] + a[10];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[7] + a[9] + a[11];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4] + a[8] + a[10];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[5] + a[9] + a[11];
   r[5] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2] + c;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2] + c;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp192r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp192r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[6];
   uint32_t v[6];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, v, u, 15);
   ecFieldMulMod(curve, u, u, v); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, v, u, a); //A^(2^31 - 1)
   ecFieldSqrMod(curve, u, v);
   ecFieldMulMod(curve, u, u, a); //A^(2^32 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^63 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^64 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^95 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^96 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^127 - 1)
   ecFieldPwr2Mod(curve, u, u, 32);
   ecFieldMulMod(curve, u, u, v); //A^(2^159 - 2^31 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^190 - 2^62 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^192 - 2^64 - 3)
}


/**
 * @brief Scalar modular reduction (secp192r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp192r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[7];
   uint32_t v[7];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 5, curve->qmu, 7);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 7);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 7);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(u, v, u, c, 7);
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(r, v, u, c, 6);
}

#endif
#if (SECP224K1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp224k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp224k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0];
   temp += (uint64_t) a[7] * 6803;
   temp += (uint64_t) a[13] * 6803;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[7] + a[13];
   temp += (uint64_t) a[8] * 6803;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[8];
   temp += (uint64_t) a[9] * 6803;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[9];
   temp += (uint64_t) a[10] * 6803;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4] + a[10];
   temp += (uint64_t) a[11] * 6803;
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[5] + a[11];
   temp += (uint64_t) a[12] * 6803;
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[6] + a[12];
   temp += (uint64_t) a[13] * 6803;
   r[6] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c * 6803;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[6];
   r[6] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c * 6803;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[6];
   r[6] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp224k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp224k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[7];
   uint32_t v[7];
   uint32_t w[7];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldPwr2Mod(curve, v, u, 2);
   ecFieldMulMod(curve, u, u, v); //A^(2^4 - 1)
   ecFieldPwr2Mod(curve, v, u, 4);
   ecFieldMulMod(curve, u, u, v); //A^(2^8 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^9 - 1)
   ecFieldPwr2Mod(curve, v, u, 9);
   ecFieldMulMod(curve, u, u, v); //A^(2^18 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, w, u, a); //A^(2^19 - 1)
   ecFieldPwr2Mod(curve, u, w, 19);
   ecFieldMulMod(curve, u, u, w); //A^(2^38 - 1)
   ecFieldPwr2Mod(curve, v, u, 38);
   ecFieldMulMod(curve, u, u, v); //A^(2^76 - 1)
   ecFieldPwr2Mod(curve, v, u, 76);
   ecFieldMulMod(curve, u, u, v); //A^(2^152 - 1)
   ecFieldPwr2Mod(curve, u, u, 19);
   ecFieldMulMod(curve, u, u, w); //A^(2^171 - 1)
   ecFieldPwr2Mod(curve, u, u, 19);
   ecFieldMulMod(curve, u, u, w); //A^(2^190 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^191 - 1)
   ecFieldPwr2Mod(curve, u, u, 20);
   ecFieldMulMod(curve, u, u, w); //A^(2^211 - 2^19 - 1)
   ecFieldPwr2Mod(curve, u, u, 3);
   ecFieldMulMod(curve, u, u, a); //A^(2^214 - 2^22 - 2^2 - 2^1 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^216 - 2^24 - 2^4 - 2^3 - 2^1 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^218 - 2^26 - 2^6 - 2^5 - 2^3 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^219 - 2^27 - 2^7 - 2^6 - 2^4 - 2^2 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^221 - 2^29 - 2^9 - 2^8 - 2^6 - 2^4 - 2^1 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^223 - 2^31 - 2^11 - 2^10 - 2^8 - 2^6 - 2^3 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, r, u, a); //A^(2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2^2 - 1)
}


/**
 * @brief Scalar modular reduction (secp224k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp224k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t a2[15];
   uint32_t q2[8];
   uint32_t u[8];
   uint32_t v[8];

   //Compute a = a << 15
   ecScalarShiftLeft(a2, a, 15, 15);
   //Compute q = q << 15
   ecScalarShiftLeft(q2, curve->q, 15, 8);

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a2 + 7, curve->qmu, 8);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, q2, 8);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a2, v, 8);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, q2, 8);
   ecScalarSelect(u, v, u, c, 8);
   c = ecScalarSub(v, u, q2, 8);
   ecScalarSelect(u, v, u, c, 8);

   //Compute a = u >> 15
   ecScalarShiftRight(r, u, 15, 8);
}

#endif
#if (SECP224R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp224r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp224r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   int64_t c;
   int64_t temp;

   //First pass
   temp = (int64_t) a[0];
   temp -= (int64_t) a[7] + a[11];
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[1];
   temp -= (int64_t) a[8] + a[12];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[2];
   temp -= (int64_t) a[9] + a[13];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[3] + a[7] + a[11];
   temp -= (int64_t) a[10];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[4] + a[8] + a[12];
   temp -= (int64_t) a[11];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[5] + a[9] + a[13];
   temp -= (int64_t) a[12];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[6] + a[10];
   temp -= (int64_t) a[13];
   r[6] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (int64_t) r[0] - c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] + c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6];
   r[6] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (int64_t) r[0] - c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] + c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6];
   r[6] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp224r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp224r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[7];
   uint32_t v[7];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, v, u, 15);
   ecFieldMulMod(curve, u, u, v); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, v, u, a); //A^(2^31 - 1)
   ecFieldSqrMod(curve, u, v);
   ecFieldMulMod(curve, u, u, a); //A^(2^32 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^63 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^64 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^95 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^96 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^127 - 1)
   ecFieldPwr2Mod(curve, u, u, 32);
   ecFieldMulMod(curve, u, u, v); //A^(2^159 - 2^31 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^160 - 2^32 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^191 - 2^63 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^192 - 2^64 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^223 - 2^95 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, r, u, a); //A^(2^224 - 2^96 - 1)
}


/**
 * @brief Scalar modular reduction (secp224r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp224r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[8];
   uint32_t v[8];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 6, curve->qmu, 8);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 8);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 8);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 8);
   ecScalarSelect(u, v, u, c, 8);
   c = ecScalarSub(v, u, curve->q, 8);
   ecScalarSelect(r, v, u, c, 7);
}

#endif
#if (SECP256K1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp256k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp256k1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0];
   temp += (uint64_t) a[8] * 977;
   temp += (uint64_t) a[15] * 977;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1] + a[8] + a[15];
   temp += (uint64_t) a[9] * 977;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2] + a[9];
   temp += (uint64_t) a[10] * 977;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3] + a[10];
   temp += (uint64_t) a[11] * 977;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4] + a[11];
   temp += (uint64_t) a[12] * 977;
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[5] + a[12];
   temp += (uint64_t) a[13] * 977;
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[6] + a[13];
   temp += (uint64_t) a[14] * 977;
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[7] + a[14];
   temp += (uint64_t) a[15] * 977;
   r[7] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (uint64_t) r[0] + c * 977;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[6];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[7];
   r[7] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (uint64_t) r[0] + c * 977;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1] + c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[6];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[7];
   r[7] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp256k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp256k1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[8];
   uint32_t v[8];
   uint32_t w[8];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldPwr2Mod(curve, v, u, 2);
   ecFieldMulMod(curve, u, u, v); //A^(2^4 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^5 - 1)
   ecFieldPwr2Mod(curve, v, u, 5);
   ecFieldMulMod(curve, u, u, v); //A^(2^10 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^11 - 1)
   ecFieldPwr2Mod(curve, v, u, 11);
   ecFieldMulMod(curve, w, u, v); //A^(2^22 - 1)
   ecFieldPwr2Mod(curve, u, w, 22);
   ecFieldMulMod(curve, u, u, w); //A^(2^44 - 1)
   ecFieldPwr2Mod(curve, v, u, 44);
   ecFieldMulMod(curve, u, u, v); //A^(2^88 - 1)
   ecFieldPwr2Mod(curve, u, u, 22);
   ecFieldMulMod(curve, u, u, w); //A^(2^110 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^111 - 1)
   ecFieldPwr2Mod(curve, v, u, 111);
   ecFieldMulMod(curve, u, u, v); //A^(2^222 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^223 - 1)
   ecFieldPwr2Mod(curve, u, u, 23);
   ecFieldMulMod(curve, u, u, w); //A^(2^246 - 2^22 - 1)
   ecFieldPwr2Mod(curve, u, u, 5);
   ecFieldMulMod(curve, u, u, a); //A^(2^251 - 2^27 - 2^4 - 2^3 - 2^2 - 2^1 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, u, u, a); //A^(2^253 - 2^29 - 2^6 - 2^5 - 2^4 - 2^3 - 2^1 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4 - 2^2 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 3)
}


/**
 * @brief Scalar modular reduction (secp256k1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp256k1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->qmu, 9);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(r, v, u, c, 8);
}

#endif
#if (SECP256R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp256r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp256r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   int64_t c;
   int64_t temp;

   //First pass
   temp = (int64_t) a[0] + a[8] + a[9];
   temp -= (int64_t) a[11] + a[12] + a[13] + a[14];
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[1] + a[9] + a[10];
   temp -= (int64_t) a[12] + a[13] + a[14] + a[15];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[2] + a[10] + a[11];
   temp -= (int64_t) a[13] + a[14] + a[15];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[3] + a[11] + a[11] + a[12] + a[12] + a[13];
   temp -= (int64_t) a[8] + a[9] + a[15];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[4] + a[12] + a[12] + a[13] + a[13] + a[14];
   temp -= (int64_t) a[9] + a[10];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[5] + a[13] + a[13] + a[14] + a[14] + a[15];
   temp -= (int64_t) a[10] + a[11];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[6] + a[13] + a[14] + a[14] + a[14] + a[15] + a[15];
   temp -= (int64_t) a[8] + a[9];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[7] + a[8] + a[15] + a[15] + a[15];
   temp -= (int64_t) a[10] + a[11] + a[12] + a[13];
   r[7] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (int64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] - c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6] - c;
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[7] + c;
   r[7] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (int64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] - c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6] - c;
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[7] + c;
   r[7] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp256r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp256r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[8];
   uint32_t v[8];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, v, u, 15);
   ecFieldMulMod(curve, u, u, v); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, v, u, a); //A^(2^31 - 1)
   ecFieldSqrMod(curve, u, v);
   ecFieldMulMod(curve, u, u, a); //A^(2^32 - 1)
   ecFieldPwr2Mod(curve, u, u, 32);
   ecFieldMulMod(curve, u, u, a); //A^(2^64 - 2^32 + 1)
   ecFieldPwr2Mod(curve, u, u, 127);
   ecFieldMulMod(curve, u, u, v); //A^(2^191 - 2^159 + 2^127 + 2^31 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^222 - 2^190 + 2^158 + 2^62 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^253 - 2^221 + 2^189 + 2^93 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^254 - 2^222 + 2^190 + 2^94 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^256 - 2^224 + 2^192 + 2^96 - 3)
}


/**
 * @brief Scalar modular reduction (secp256r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp256r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->qmu, 9);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(r, v, u, c, 8);
}


/**
 * @brief Scalar modular inversion (secp256r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod q
 * @param[in] a An integer such as 0 <= A < q
 **/

void secp256r1ScalarInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   int_t i;
   uint32_t u[13];
   uint32_t v[13];

   //Process bits 255...128
   ecScalarSqrMod(curve, u, a);
   ecScalarMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecScalarPwr2Mod(curve, v, u, 2);
   ecScalarMulMod(curve, u, u, v); //A^(2^4 - 1)
   ecScalarPwr2Mod(curve, v, u, 4);
   ecScalarMulMod(curve, u, u, v); //A^(2^8 - 1)
   ecScalarPwr2Mod(curve, v, u, 8);
   ecScalarMulMod(curve, u, u, v); //A^(2^16 - 1)
   ecScalarPwr2Mod(curve, v, u, 16);
   ecScalarMulMod(curve, v, u, v); //A^(2^32 - 1)
   ecScalarPwr2Mod(curve, u, v, 64);
   ecScalarMulMod(curve, u, u, v);
   ecScalarPwr2Mod(curve, u, u, 32);
   ecScalarMulMod(curve, u, u, v);

   //Process bits 127..5
   for(i = 127; i >= 5; i--)
   {
      //Calculate U = U^2
      ecScalarSqrMod(curve, u, u);

      //Check the value of q(i)
      if(((curve->q[i / 32] >> (i % 32)) & 1) != 0)
      {
         //Calculate U = U * A
         ecScalarMulMod(curve, u, u, a);
      }
   }

   //Process bits 4..0
   ecScalarSqrMod(curve, u, u);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, r, u, a);
}

#endif
#if (SECP384R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp384r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp384r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   int64_t c;
   int64_t temp;

   //First pass
   temp = (int64_t) a[0] + a[12] + a[20] + a[21];
   temp -= (int64_t) a[23];
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[1] + a[13] + a[22] + a[23];
   temp -= (int64_t) a[12] + a[20];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[2] + a[14] + a[23];
   temp -= (int64_t) a[13] + a[21];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[3] + a[12] + a[15] + a[20] + a[21];
   temp -= (int64_t) a[14] + a[22] + a[23];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[4] + a[12] + a[13] + a[16] + a[20] + a[21] + a[21] + a[22];
   temp -= (int64_t) a[15] + a[23] + a[23];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[5] + a[13] + a[14] + a[17] + a[21] + a[22] + a[22] + a[23];
   temp -= (int64_t) a[16];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[6] + a[14] + a[15] + a[18] + a[22] + a[23] + a[23];
   temp -= (int64_t) a[17];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[7] + a[15] + a[16] + a[19] + a[23];
   temp -= (int64_t) a[18];
   r[7] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[8] + a[16] + a[17] + a[20];
   temp -= (int64_t) a[19];
   r[8] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[9] + a[17] + a[18] + a[21];
   temp -= (int64_t) a[20];
   r[9] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[10] + a[18] + a[19] + a[22];
   temp -= (int64_t) a[21];
   r[10] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[11] + a[19] + a[20] + a[23];
   temp -= (int64_t) a[22];
   r[11] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (int64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1] - c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] + c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4] + c;
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[7];
   r[7] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[8];
   r[8] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[9];
   r[9] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[10];
   r[10] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[11];
   r[11] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (int64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1] - c;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] + c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4] + c;
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[7];
   r[7] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[8];
   r[8] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[9];
   r[9] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[10];
   r[10] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[11];
   r[11] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp384r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp384r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[12];
   uint32_t v[12];
   uint32_t w[12];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, v, u, 15);
   ecFieldMulMod(curve, w, u, v); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, w);
   ecFieldMulMod(curve, u, u, a); //A^(2^31 - 1)
   ecFieldPwr2Mod(curve, v, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^62 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^63 - 1)
   ecFieldPwr2Mod(curve, v, u, 63);
   ecFieldMulMod(curve, u, u, v); //A^(2^126 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^127 - 1)
   ecFieldPwr2Mod(curve, v, u, 127);
   ecFieldMulMod(curve, u, u, v); //A^(2^254 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^255 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, w); //A^(2^286 - 2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^287 - 2^31 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^288 - 2^32 - 1)
   ecFieldPwr2Mod(curve, u, u, 94);
   ecFieldMulMod(curve, u, u, w); //A^(2^382 - 2^126 - 2^94 + 2^30 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^384 - 2^128 - 2^96 + 2^32 - 3)
}


/**
 * @brief Scalar modular reduction (secp384r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp384r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[13];
   uint32_t v[13];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 11, curve->qmu, 13);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 13);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 13);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 13);
   ecScalarSelect(u, v, u, c, 13);
   c = ecScalarSub(v, u, curve->q, 13);
   ecScalarSelect(r, v, u, c, 12);
}


/**
 * @brief Scalar modular inversion (secp384r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod q
 * @param[in] a An integer such as 0 <= A < q
 **/

void secp384r1ScalarInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   int_t i;
   uint32_t u[13];
   uint32_t v[13];

   //Process bits 383...190
   ecScalarSqrMod(curve, u, a);
   ecScalarMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecScalarPwr2Mod(curve, v, u, 3);
   ecScalarMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecScalarPwr2Mod(curve, v, u, 6);
   ecScalarMulMod(curve, u, u, v); //A^(2^12 - 1)
   ecScalarPwr2Mod(curve, v, u, 12);
   ecScalarMulMod(curve, u, u, v); //A^(2^24 - 1)
   ecScalarPwr2Mod(curve, v, u, 24);
   ecScalarMulMod(curve, u, u, v); //A^(2^48 - 1)
   ecScalarPwr2Mod(curve, v, u, 48);
   ecScalarMulMod(curve, u, u, v); //A^(2^96 - 1)
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a); //A^(2^97 - 1)
   ecScalarPwr2Mod(curve, v, u, 97);
   ecScalarMulMod(curve, u, u, v); //A^(2^194 - 1)

   //Process bits 189..2
   for(i = 189; i >= 2; i--)
   {
      //Calculate U = U^2
      ecScalarSqrMod(curve, u, u);

      //Check the value of q(i)
      if(((curve->q[i / 32] >> (i % 32)) & 1) != 0)
      {
         //Calculate U = U * A
         ecScalarMulMod(curve, u, u, a);
      }
   }

   //Process bits 1..0
   ecScalarSqrMod(curve, u, u);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, r, u, a);
}

#endif
#if (SECP521R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (secp521r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void secp521r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint64_t c;
   uint64_t temp;

   //First pass
   temp = (uint64_t) a[0];
   temp += (uint64_t) a[16] >> 9;
   temp += (uint64_t) a[17] << 23;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[1];
   temp += (uint64_t) a[18] << 23;
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[2];
   temp += (uint64_t) a[19] << 23;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[3];
   temp += (uint64_t) a[20] << 23;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[4];
   temp += (uint64_t) a[21] << 23;
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[5];
   temp += (uint64_t) a[22] << 23;
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[6];
   temp += (uint64_t) a[23] << 23;
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[7];
   temp += (uint64_t) a[24] << 23;
   r[7] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[8];
   temp += (uint64_t) a[25] << 23;
   r[8] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[9];
   temp += (uint64_t) a[26] << 23;
   r[9] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[10];
   temp += (uint64_t) a[27] << 23;
   r[10] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[11];
   temp += (uint64_t) a[28] << 23;
   r[11] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[12];
   temp += (uint64_t) a[29] << 23;
   r[12] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[13];
   temp += (uint64_t) a[30] << 23;
   r[13] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[14];
   temp += (uint64_t) a[31] << 23;
   r[14] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[15];
   temp += (uint64_t) a[32] << 23;
   r[15] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) a[16] & 0x1FF;
   r[16] = (uint32_t) temp & 0x1FF;
   c = temp >> 9;

   //Second pass
   temp = (uint64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[2];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[3];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[6];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[7];
   r[7] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[8];
   r[8] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[9];
   r[9] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[10];
   r[10] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[11];
   r[11] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[12];
   r[12] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[13];
   r[13] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[14];
   r[14] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[15];
   r[15] = (uint32_t) temp;
   temp >>= 32;
   temp += (uint64_t) r[16] & 0x1FF;
   r[16] = (uint32_t) temp & 0x1FF;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (secp521r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void secp521r1FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[17];
   uint32_t v[17];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldPwr2Mod(curve, v, u, 2);
   ecFieldMulMod(curve, u, u, v); //A^(2^4 - 1)
   ecFieldPwr2Mod(curve, v, u, 4);
   ecFieldMulMod(curve, u, u, v); //A^(2^8 - 1)
   ecFieldPwr2Mod(curve, v, u, 8);
   ecFieldMulMod(curve, u, u, v); //A^(2^16 - 1)
   ecFieldPwr2Mod(curve, v, u, 16);
   ecFieldMulMod(curve, u, u, v); //A^(2^32 - 1)
   ecFieldPwr2Mod(curve, v, u, 32);
   ecFieldMulMod(curve, u, u, v); //A^(2^64 - 1)
   ecFieldPwr2Mod(curve, v, u, 64);
   ecFieldMulMod(curve, u, u, v); //A^(2^128 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^129 - 1)
   ecFieldPwr2Mod(curve, v, u, 129);
   ecFieldMulMod(curve, u, u, v); //A^(2^258 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^259 - 1)
   ecFieldPwr2Mod(curve, v, u, 259);
   ecFieldMulMod(curve, u, u, v); //A^(2^518 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^519 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^521 - 3)
}


/**
 * @brief Scalar modular reduction (secp521r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void secp521r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t a2[33];
   uint32_t q2[17];
   uint32_t u[17];
   uint32_t v[17];

   //Compute a = a << 7
   ecScalarShiftLeft(a2, a, 7, 33);
   //Compute q = q << 7
   ecScalarShiftLeft(q2, curve->q, 7, 17);

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a2 + 16, curve->qmu, 17);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, q2, 17);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a2, v, 17);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, q2, 17);
   ecScalarSelect(u, v, u, c, 17);
   c = ecScalarSub(v, u, q2, 17);
   ecScalarSelect(u, v, u, c, 17);

   //Compute a = u >> 7
   ecScalarShiftRight(r, u, 7, 17);
}


/**
 * @brief Scalar modular inversion (secp521r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod q
 * @param[in] a An integer such as 0 <= A < q
 **/

void secp521r1ScalarInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   int_t i;
   uint32_t u[17];
   uint32_t v[17];

   //Process bits 520...259
   ecScalarSqrMod(curve, u, a);
   ecScalarMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecScalarPwr2Mod(curve, v, u, 2);
   ecScalarMulMod(curve, u, u, v); //A^(2^4 - 1)
   ecScalarPwr2Mod(curve, v, u, 4);
   ecScalarMulMod(curve, u, u, v); //A^(2^8 - 1)
   ecScalarPwr2Mod(curve, v, u, 8);
   ecScalarMulMod(curve, u, u, v); //A^(2^16 - 1)
   ecScalarPwr2Mod(curve, v, u, 16);
   ecScalarMulMod(curve, u, u, v); //A^(2^32 - 1)
   ecScalarPwr2Mod(curve, v, u, 32);
   ecScalarMulMod(curve, u, u, v); //A^(2^64 - 1)
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a); //A^(2^65 - 1)
   ecScalarPwr2Mod(curve, v, u, 65);
   ecScalarMulMod(curve, u, u, v); //A^(2^130 - 1)
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a); //A^(2^131 - 1)
   ecScalarPwr2Mod(curve, v, u, 131);
   ecScalarMulMod(curve, u, u, v); //A^(2^262 - 1)

   //Process bits 258..4
   for(i = 258; i >= 4; i--)
   {
      //Calculate U = U^2
      ecScalarSqrMod(curve, u, u);

      //Check the value of q(i)
      if(((curve->q[i / 32] >> (i % 32)) & 1) != 0)
      {
         //Calculate U = U * A
         ecScalarMulMod(curve, u, u, a);
      }
   }

   //Process bits 3..0
   ecScalarSqrMod(curve, u, u);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, u, u, a);
   ecScalarSqrMod(curve, u, u);
   ecScalarMulMod(curve, r, u, a);
}

#endif
#if (BRAINPOOLP160R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP160r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP160r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[6];
   uint32_t v[6];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 4, curve->pmu, 6);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 6);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 6);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 6);
   ecScalarSelect(u, v, u, c, 6);
   c = ecScalarSub(v, u, curve->p, 6);
   ecScalarSelect(r, v, u, c, 5);
}


/**
 * @brief Scalar modular reduction (brainpoolP160r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP160r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[6];
   uint32_t v[6];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 4, curve->qmu, 6);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 6);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 6);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 6);
   ecScalarSelect(u, v, u, c, 6);
   c = ecScalarSub(v, u, curve->q, 6);
   ecScalarSelect(r, v, u, c, 5);
}

#endif
#if (BRAINPOOLP160T1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP160t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP160t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[6];
   uint32_t v[6];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 4, curve->pmu, 6);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 6);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 6);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 6);
   ecScalarSelect(u, v, u, c, 6);
   c = ecScalarSub(v, u, curve->p, 6);
   ecScalarSelect(r, v, u, c, 5);
}


/**
 * @brief Scalar modular reduction (brainpoolP160t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP160t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[6];
   uint32_t v[6];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 4, curve->qmu, 6);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 6);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 6);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 6);
   ecScalarSelect(u, v, u, c, 6);
   c = ecScalarSub(v, u, curve->q, 6);
   ecScalarSelect(r, v, u, c, 5);
}

#endif
#if (BRAINPOOLP192R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP192r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP192r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[7];
   uint32_t v[7];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 5, curve->pmu, 7);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 7);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 7);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 7);
   ecScalarSelect(u, v, u, c, 7);
   c = ecScalarSub(v, u, curve->p, 7);
   ecScalarSelect(r, v, u, c, 6);
}


/**
 * @brief Scalar modular reduction (brainpoolP192r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP192r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[7];
   uint32_t v[7];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 5, curve->qmu, 7);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 7);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 7);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(u, v, u, c, 7);
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(r, v, u, c, 6);
}

#endif
#if (BRAINPOOLP192T1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP192t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP192t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[7];
   uint32_t v[7];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 5, curve->pmu, 7);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 7);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 7);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 7);
   ecScalarSelect(u, v, u, c, 7);
   c = ecScalarSub(v, u, curve->p, 7);
   ecScalarSelect(r, v, u, c, 6);
}


/**
 * @brief Scalar modular reduction (brainpoolP192t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP192t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[7];
   uint32_t v[7];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 5, curve->qmu, 7);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 7);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 7);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(u, v, u, c, 7);
   c = ecScalarSub(v, u, curve->q, 7);
   ecScalarSelect(r, v, u, c, 6);
}

#endif
#if (BRAINPOOLP224R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP224r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP224r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[8];
   uint32_t v[8];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 6, curve->pmu, 8);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 8);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 8);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 8);
   ecScalarSelect(u, v, u, c, 8);
   c = ecScalarSub(v, u, curve->p, 8);
   ecScalarSelect(r, v, u, c, 7);
}


/**
 * @brief Scalar modular reduction (brainpoolP224r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP224r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[8];
   uint32_t v[8];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 6, curve->qmu, 8);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 8);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 8);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 8);
   ecScalarSelect(u, v, u, c, 8);
   c = ecScalarSub(v, u, curve->q, 8);
   ecScalarSelect(r, v, u, c, 7);
}

#endif
#if (BRAINPOOLP224T1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP224t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP224t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[8];
   uint32_t v[8];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 6, curve->pmu, 8);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 8);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 8);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 8);
   ecScalarSelect(u, v, u, c, 8);
   c = ecScalarSub(v, u, curve->p, 8);
   ecScalarSelect(r, v, u, c, 7);
}


/**
 * @brief Scalar modular reduction (brainpoolP224t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP224t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[8];
   uint32_t v[8];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 6, curve->qmu, 8);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 8);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 8);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 8);
   ecScalarSelect(u, v, u, c, 8);
   c = ecScalarSub(v, u, curve->q, 8);
   ecScalarSelect(r, v, u, c, 7);
}

#endif
#if (BRAINPOOLP256R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP256r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP256r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->pmu, 9);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->p, 9);
   ecScalarSelect(r, v, u, c, 8);
}


/**
 * @brief Scalar modular reduction (brainpoolP256r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP256r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->qmu, 9);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(r, v, u, c, 8);
}

#endif
#if (BRAINPOOLP256T1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP256t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP256t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->pmu, 9);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->p, 9);
   ecScalarSelect(r, v, u, c, 8);
}


/**
 * @brief Scalar modular reduction (brainpoolP256t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP256t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->qmu, 9);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(r, v, u, c, 8);
}

#endif
#if (BRAINPOOLP320R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP320r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP320r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[11];
   uint32_t v[11];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 9, curve->pmu, 11);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 11);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 11);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 11);
   ecScalarSelect(u, v, u, c, 11);
   c = ecScalarSub(v, u, curve->p, 11);
   ecScalarSelect(r, v, u, c, 10);
}


/**
 * @brief Scalar modular reduction (brainpoolP320r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP320r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[11];
   uint32_t v[11];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 9, curve->qmu, 11);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 11);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 11);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 11);
   ecScalarSelect(u, v, u, c, 11);
   c = ecScalarSub(v, u, curve->q, 11);
   ecScalarSelect(r, v, u, c, 10);
}

#endif
#if (BRAINPOOLP320T1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP320t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP320t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[11];
   uint32_t v[11];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 9, curve->pmu, 11);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 11);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 11);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 11);
   ecScalarSelect(u, v, u, c, 11);
   c = ecScalarSub(v, u, curve->p, 11);
   ecScalarSelect(r, v, u, c, 10);
}


/**
 * @brief Scalar modular reduction (brainpoolP320t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP320t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[11];
   uint32_t v[11];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 9, curve->qmu, 11);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 11);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 11);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 11);
   ecScalarSelect(u, v, u, c, 11);
   c = ecScalarSub(v, u, curve->q, 11);
   ecScalarSelect(r, v, u, c, 10);
}

#endif
#if (BRAINPOOLP384R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP384r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP384r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[13];
   uint32_t v[13];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 11, curve->pmu, 13);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 13);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 13);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 13);
   ecScalarSelect(u, v, u, c, 13);
   c = ecScalarSub(v, u, curve->p, 13);
   ecScalarSelect(r, v, u, c, 12);
}


/**
 * @brief Scalar modular reduction (brainpoolP384r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP384r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[13];
   uint32_t v[13];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 11, curve->qmu, 13);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 13);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 13);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 13);
   ecScalarSelect(u, v, u, c, 13);
   c = ecScalarSub(v, u, curve->q, 13);
   ecScalarSelect(r, v, u, c, 12);
}

#endif
#if (BRAINPOOLP384T1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP384t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP384t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[13];
   uint32_t v[13];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 11, curve->pmu, 13);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 13);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 13);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 13);
   ecScalarSelect(u, v, u, c, 13);
   c = ecScalarSub(v, u, curve->p, 13);
   ecScalarSelect(r, v, u, c, 12);
}


/**
 * @brief Scalar modular reduction (brainpoolP384t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP384t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[13];
   uint32_t v[13];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 11, curve->qmu, 13);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 13);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 13);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 13);
   ecScalarSelect(u, v, u, c, 13);
   c = ecScalarSub(v, u, curve->q, 13);
   ecScalarSelect(r, v, u, c, 12);
}

#endif
#if (BRAINPOOLP512R1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP512r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP512r1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[17];
   uint32_t v[17];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 15, curve->pmu, 17);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 17);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 17);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 17);
   ecScalarSelect(u, v, u, c, 17);
   c = ecScalarSub(v, u, curve->p, 17);
   ecScalarSelect(r, v, u, c, 16);
}


/**
 * @brief Scalar modular reduction (brainpoolP512r1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP512r1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[17];
   uint32_t v[17];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 15, curve->qmu, 17);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 17);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 17);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 17);
   ecScalarSelect(u, v, u, c, 17);
   c = ecScalarSub(v, u, curve->q, 17);
   ecScalarSelect(r, v, u, c, 16);
}

#endif
#if (BRAINPOOLP512T1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (brainpoolP512t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void brainpoolP512t1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[17];
   uint32_t v[17];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 15, curve->pmu, 17);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 17);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 17);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 17);
   ecScalarSelect(u, v, u, c, 17);
   c = ecScalarSub(v, u, curve->p, 17);
   ecScalarSelect(r, v, u, c, 16);
}


/**
 * @brief Scalar modular reduction (brainpoolP512t1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void brainpoolP512t1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[17];
   uint32_t v[17];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 15, curve->qmu, 17);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 17);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 17);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 17);
   ecScalarSelect(u, v, u, c, 17);
   c = ecScalarSub(v, u, curve->q, 17);
   ecScalarSelect(r, v, u, c, 16);
}

#endif
#if (FRP256V1_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (FRP256v1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void frp256v1FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->pmu, 9);
   //Compute v = u * p mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->p, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of p are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->p, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->p, 9);
   ecScalarSelect(r, v, u, c, 8);
}


/**
 * @brief Scalar modular reduction (FRP256v1 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void frp256v1ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->qmu, 9);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(r, v, u, c, 8);
}

#endif
#if (SM2_SUPPORT == ENABLED)

/**
 * @brief Field modular reduction (SM2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < p^2
 **/

void sm2FieldMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   int64_t c;
   int64_t temp;

   //First pass
   temp = (int64_t) a[0] + a[8] + a[9] + a[10] + a[11] + a[12] + a[13] + a[13];
   temp += (int64_t) a[14] + a[14] + a[15] + a[15];
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[1] + a[9] + a[10] + a[11] + a[12] + a[13] + a[14] + a[14];
   temp += (int64_t) a[15] + a[15];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[2];
   temp -= (int64_t) a[8] + a[9] + a[13] + a[14];
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[3] + a[8] + a[11] + a[12] + a[13] + a[13] + a[14] + a[15];
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[4] + a[9] + a[12] + a[13] + a[14] + a[14] + a[15];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[5] + a[10] + a[13] + a[14] + a[15] + a[15];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[6] + a[11] + a[14] + a[15];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) a[7] + a[8] + a[9] + a[10] + a[11] + a[12] + a[12] + a[13];
   temp += (int64_t) a[13] + a[14] + a[14] + a[15] + a[15] + a[15];
   r[7] = (uint32_t) temp;
   c = temp >> 32;

   //Second pass
   temp = (int64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2] - c;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] + c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[7] + c;
   r[7] = (uint32_t) temp;
   c = temp >> 32;

   //Third pass
   temp = (int64_t) r[0] + c;
   r[0] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[1];
   r[1] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[2] - c;
   r[2] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[3] + c;
   r[3] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[4];
   r[4] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[5];
   r[5] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[6];
   r[6] = (uint32_t) temp;
   temp >>= 32;
   temp += (int64_t) r[7] + c;
   r[7] = (uint32_t) temp;

   //Reduce non-canonical values
   ecFieldCanonicalize(curve, r, r);
}


/**
 * @brief Field modular inversion (SM2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void sm2FieldInv(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t u[8];
   uint32_t v[8];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   ecFieldSqrMod(curve, u, a);
   ecFieldMulMod(curve, u, u, a); //A^(2^2 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^3 - 1)
   ecFieldPwr2Mod(curve, v, u, 3);
   ecFieldMulMod(curve, u, u, v); //A^(2^6 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^7 - 1)
   ecFieldPwr2Mod(curve, v, u, 7);
   ecFieldMulMod(curve, u, u, v); //A^(2^14 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^15 - 1)
   ecFieldPwr2Mod(curve, v, u, 15);
   ecFieldMulMod(curve, u, u, v); //A^(2^30 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, v, u, a); //A^(2^31 - 1)
   ecFieldPwr2Mod(curve, u, v, 32);
   ecFieldMulMod(curve, u, u, v); //A^(2^63 - 2^31 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^64 - 2^32 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^95 - 2^63 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^96 - 2^64 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^127 - 2^95 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^128 - 2^96 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^159 - 2^127 - 1)
   ecFieldSqrMod(curve, u, u);
   ecFieldMulMod(curve, u, u, a); //A^(2^160 - 2^128 - 1)
   ecFieldPwr2Mod(curve, u, u, 63);
   ecFieldMulMod(curve, u, u, v); //A^(2^223 - 2^191 - 2^63 + 2^31 - 1)
   ecFieldPwr2Mod(curve, u, u, 31);
   ecFieldMulMod(curve, u, u, v); //A^(2^254 - 2^222 - 2^94 + 2^62 - 1)
   ecFieldPwr2Mod(curve, u, u, 2);
   ecFieldMulMod(curve, r, u, a); //A^(2^256 - 2^224 - 2^96 + 2^64 - 3)
}


/**
 * @brief Scalar modular reduction (SM2 curve)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod q
 * @param[in] a An integer such as 0 <= A < q^2
 **/

void sm2ScalarMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint32_t c;
   uint32_t u[9];
   uint32_t v[9];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ecScalarMul(NULL, u, a + 7, curve->qmu, 9);
   //Compute v = u * q mod b^(k + 1)
   ecScalarMul(v, NULL, u, curve->q, 9);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ecScalarSub(u, a, v, 9);

   //This estimation implies that at most two subtractions of q are required to
   //obtain the correct remainder r
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(u, v, u, c, 9);
   c = ecScalarSub(v, u, curve->q, 9);
   ecScalarSelect(r, v, u, c, 8);
}

#endif


/**
 * @brief Get the elliptic curve that matches the specified OID
 * @param[in] oid Object identifier
 * @param[in] length OID length
 * @return Elliptic curve parameters
 **/

const EcCurve *ecGetCurve(const uint8_t *oid, size_t length)
{
   const EcCurve *curve;

   //Invalid parameters?
   if(oid == NULL || length == 0)
   {
      curve = NULL;
   }
#if (SECP112R1_SUPPORT == ENABLED)
   //secp112r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP112R1_OID) == 0)
   {
      curve = SECP112R1_CURVE;
   }
#endif
#if (SECP112R2_SUPPORT == ENABLED)
   //secp112r2 elliptic curve?
   else if(OID_COMP(oid, length, SECP112R2_OID) == 0)
   {
      curve = SECP112R2_CURVE;
   }
#endif
#if (SECP128R1_SUPPORT == ENABLED)
   //secp128r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP128R1_OID) == 0)
   {
      curve = SECP128R1_CURVE;
   }
#endif
#if (SECP128R2_SUPPORT == ENABLED)
   //secp128r2 elliptic curve?
   else if(OID_COMP(oid, length, SECP128R2_OID) == 0)
   {
      curve = SECP128R2_CURVE;
   }
#endif
#if (SECP160K1_SUPPORT == ENABLED)
   //secp160k1 elliptic curve?
   else if(OID_COMP(oid, length, SECP160K1_OID) == 0)
   {
      curve = SECP160K1_CURVE;
   }
#endif
#if (SECP160R1_SUPPORT == ENABLED)
   //secp160r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP160R1_OID) == 0)
   {
      curve = SECP160R1_CURVE;
   }
#endif
#if (SECP160R2_SUPPORT == ENABLED)
   //secp160r2 elliptic curve?
   else if(OID_COMP(oid, length, SECP160R2_OID) == 0)
   {
      curve = SECP160R2_CURVE;
   }
#endif
#if (SECP192K1_SUPPORT == ENABLED)
   //secp192k1 elliptic curve?
   else if(OID_COMP(oid, length, SECP192K1_OID) == 0)
   {
      curve = SECP192K1_CURVE;
   }
#endif
#if (SECP192R1_SUPPORT == ENABLED)
   //secp192r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP192R1_OID) == 0)
   {
      curve = SECP192R1_CURVE;
   }
#endif
#if (SECP224K1_SUPPORT == ENABLED)
   //secp224k1 elliptic curve?
   else if(OID_COMP(oid, length, SECP224K1_OID) == 0)
   {
      curve = SECP224K1_CURVE;
   }
#endif
#if (SECP224R1_SUPPORT == ENABLED)
   //secp224r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP224R1_OID) == 0)
   {
      curve = SECP224R1_CURVE;
   }
#endif
#if (SECP256K1_SUPPORT == ENABLED)
   //secp256k1 elliptic curve?
   else if(OID_COMP(oid, length, SECP256K1_OID) == 0)
   {
      curve = SECP256K1_CURVE;
   }
#endif
#if (SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP256R1_OID) == 0)
   {
      curve = SECP256R1_CURVE;
   }
#endif
#if (SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP384R1_OID) == 0)
   {
      curve = SECP384R1_CURVE;
   }
#endif
#if (SECP521R1_SUPPORT == ENABLED)
   //secp521r1 elliptic curve?
   else if(OID_COMP(oid, length, SECP521R1_OID) == 0)
   {
      curve = SECP521R1_CURVE;
   }
#endif
#if (BRAINPOOLP160R1_SUPPORT == ENABLED)
   //brainpoolP160r1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP160R1_OID) == 0)
   {
      curve = BRAINPOOLP160R1_CURVE;
   }
#endif
#if (BRAINPOOLP160T1_SUPPORT == ENABLED)
   //brainpoolP160t1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP160T1_OID) == 0)
   {
      curve = BRAINPOOLP160T1_CURVE;
   }
#endif
#if (BRAINPOOLP192R1_SUPPORT == ENABLED)
   //brainpoolP192r1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP192R1_OID) == 0)
   {
      curve = BRAINPOOLP192R1_CURVE;
   }
#endif
#if (BRAINPOOLP192T1_SUPPORT == ENABLED)
   //brainpoolP192t1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP192T1_OID) == 0)
   {
      curve = BRAINPOOLP192T1_CURVE;
   }
#endif
#if (BRAINPOOLP224R1_SUPPORT == ENABLED)
   //brainpoolP224r1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP224R1_OID) == 0)
   {
      curve = BRAINPOOLP224R1_CURVE;
   }
#endif
#if (BRAINPOOLP224T1_SUPPORT == ENABLED)
   //brainpoolP224t1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP224T1_OID) == 0)
   {
      curve = BRAINPOOLP224T1_CURVE;
   }
#endif
#if (BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP256R1_OID) == 0)
   {
      curve = BRAINPOOLP256R1_CURVE;
   }
#endif
#if (BRAINPOOLP256T1_SUPPORT == ENABLED)
   //brainpoolP256t1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP256T1_OID) == 0)
   {
      curve = BRAINPOOLP256T1_CURVE;
   }
#endif
#if (BRAINPOOLP320R1_SUPPORT == ENABLED)
   //brainpoolP320r1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP320R1_OID) == 0)
   {
      curve = BRAINPOOLP320R1_CURVE;
   }
#endif
#if (BRAINPOOLP320T1_SUPPORT == ENABLED)
   //brainpoolP320t1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP320T1_OID) == 0)
   {
      curve = BRAINPOOLP320T1_CURVE;
   }
#endif
#if (BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP384R1_OID) == 0)
   {
      curve = BRAINPOOLP384R1_CURVE;
   }
#endif
#if (BRAINPOOLP384T1_SUPPORT == ENABLED)
   //brainpoolP384t1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP384T1_OID) == 0)
   {
      curve = BRAINPOOLP384T1_CURVE;
   }
#endif
#if (BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP512R1_OID) == 0)
   {
      curve = BRAINPOOLP512R1_CURVE;
   }
#endif
#if (BRAINPOOLP512T1_SUPPORT == ENABLED)
   //brainpoolP512t1 elliptic curve?
   else if(OID_COMP(oid, length, BRAINPOOLP512T1_OID) == 0)
   {
      curve = BRAINPOOLP512T1_CURVE;
   }
#endif
#if (FRP256V1_SUPPORT == ENABLED)
   //FRP256v1 elliptic curve?
   else if(OID_COMP(oid, length, FRP256V1_OID) == 0)
   {
      curve = FRP256V1_CURVE;
   }
#endif
#if (SM2_SUPPORT == ENABLED)
   //SM2 elliptic curve?
   else if(OID_COMP(oid, length, SM2_OID) == 0)
   {
      curve = SM2_CURVE;
   }
#endif
#if (X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   else if(OID_COMP(oid, length, X25519_OID) == 0)
   {
      curve = X25519_CURVE;
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   else if(OID_COMP(oid, length, X448_OID) == 0)
   {
      curve = X448_CURVE;
   }
#endif
#if (ED25519_SUPPORT == ENABLED)
   //Ed25519 elliptic curve?
   else if(OID_COMP(oid, length, ED25519_OID) == 0)
   {
      curve = ED25519_CURVE;
   }
#endif
#if (ED448_SUPPORT == ENABLED)
   //Ed448 elliptic curve?
   else if(OID_COMP(oid, length, ED448_OID) == 0)
   {
      curve = ED448_CURVE;
   }
#endif
   //Unknown identifier?
   else
   {
      curve = NULL;
   }

   //Return the elliptic curve parameters, if any
   return curve;
}

#endif
