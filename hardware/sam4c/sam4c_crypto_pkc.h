/**
 * @file sam4c_crypto_pkc.h
 * @brief SAM4C public-key hardware accelerator (CPKCC)
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
 * @version 2.5.0
 **/

#ifndef _SAM4C_CRYPTO_PKC_H
#define _SAM4C_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef SAM4C_CRYPTO_PKC_SUPPORT
   #define SAM4C_CRYPTO_PKC_SUPPORT DISABLED
#elif (SAM4C_CRYPTO_PKC_SUPPORT != ENABLED && SAM4C_CRYPTO_PKC_SUPPORT != DISABLED)
   #error SAM4C_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//Crypto memory base address
#define CPKCC_CRYPTO_RAM_BASE 0x20191000UL

//Far to near pointer conversion
#define CPKCC_FAR_TO_NEAR(p) ((uint16_t) ((uint32_t) (p)))

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Elliptic curve point
 **/

typedef struct
{
   uint8_t *x;
   uint8_t *y;
   uint8_t *z;
} PukccEcPoint;


/**
 * @brief Fmult service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   uint8_t *x;
   uint8_t *y;
   uint8_t *z;
   uint8_t *r;
} PukccFmultParams;


/**
 * @brief GCD service parameters
 **/

typedef struct
{
   uint8_t *x;
   uint8_t *y;
   uint8_t *a;
   uint8_t *z;
   uint8_t *w;
} PukccGcdParams;


/**
 * @brief RedMod service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   uint8_t *exp;
   uint8_t *r;
   uint8_t *x;
} PukccRedModParams;


/**
 * @brief ExpMod service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   uint8_t *exp;
   uint8_t *r;
   uint8_t *x;
   uint8_t *w;
} PukccExpModParams;


/**
 * @brief PrimeGen service parameters
 **/

typedef struct
{
   uint8_t *n;
   uint8_t *cns;
   uint8_t *rnd;
   uint8_t *w;
   uint8_t *r;
   uint8_t *exp;
} PukccPrimeGenParams;


/**
 * @brief CRT service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *x;
   uint8_t *exp;
   uint8_t *p;
   uint8_t *q;
   uint8_t *dp;
   uint8_t *dq;
   uint8_t *r;
} PukccCrtParams;


/**
 * @brief ZpEcPointIsOnCurve service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   PukccEcPoint point;
   uint8_t *a;
   uint8_t *b;
   uint8_t *r;
   uint8_t *x;
   uint8_t *w;
} PukccZpEcPointIsOnCurveParams;


/**
 * @brief ZpEcConvProjToAffine service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   uint8_t *k;
   PukccEcPoint point;
   uint8_t *r;
   uint8_t *x;
   uint8_t *w;
} PukccZpEcConvProjToAffineParams;


/**
 * @brief ZpEccMul service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   uint8_t *k;
   PukccEcPoint point;
   uint8_t *a;
   uint8_t *r;
   uint8_t *x;
   uint8_t *w;
} PukccZpEccMulParams;


/**
 * @brief ZpEcDsaGenerate service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   PukccEcPoint basePoint;
   uint8_t *order;
   uint8_t *a;
   uint8_t *privateKey;
   uint8_t *k;
   uint8_t *h;
   uint8_t *r;
   uint8_t *x;
   uint8_t *w;
} PukccZpEcDsaGenerateParams;


/**
 * @brief ZpEcDsaVerify service parameters
 **/

typedef struct
{
   uint8_t *mod;
   uint8_t *cns;
   PukccEcPoint basePoint;
   uint8_t *order;
   uint8_t *a;
   PukccEcPoint publicKey;
   uint8_t *h;
   uint8_t *r;
   uint8_t *s;
   uint8_t *x;
   uint8_t *w;
} PukccZpEcDsaVerifyParams;


//CPKCC related functions
error_t cpkccInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
