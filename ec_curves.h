/**
 * @file ec_curves.h
 * @brief Elliptic curves
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.7.6
 **/

#ifndef _EC_CURVES_H
#define _EC_CURVES_H

//Dependencies
#include "crypto.h"
#include "mpi.h"

//SECG curves
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

//Brainpool curves
#define BRAINPOOLP160R1_CURVE (&brainpoolP160r1Curve)
#define BRAINPOOLP192R1_CURVE (&brainpoolP192r1Curve)
#define BRAINPOOLP224R1_CURVE (&brainpoolP224r1Curve)
#define BRAINPOOLP256R1_CURVE (&brainpoolP256r1Curve)
#define BRAINPOOLP320R1_CURVE (&brainpoolP320r1Curve)
#define BRAINPOOLP384R1_CURVE (&brainpoolP384r1Curve)
#define BRAINPOOLP512R1_CURVE (&brainpoolP512r1Curve)


/**
 * @brief Elliptic curve type
 **/

typedef enum
{
   EC_CURVE_TYPE_NONE          = 0,
   EC_CURVE_TYPE_SECT_K1       = 1,
   EC_CURVE_TYPE_SECT_R1       = 2,
   EC_CURVE_TYPE_SECT_R2       = 3,
   EC_CURVE_TYPE_SECP_K1       = 4,
   EC_CURVE_TYPE_SECP_R1       = 5,
   EC_CURVE_TYPE_SECP_R2       = 6,
   EC_CURVE_TYPE_BRAINPOOLP_R1 = 7
} EcCurveType;


/**
 * @brief Fast modular reduction
 **/

typedef error_t (*EcFastModAlgo)(Mpi *a, const Mpi *p);


/**
 * @brief Elliptic curve parameters
 **/

typedef struct
{
   const char_t *name;   ///<Curve name
   const uint8_t *oid;   ///<Object identifier
   size_t oidSize;       ///<OID size
   EcCurveType type;     ///<Curve type
   const uint8_t p[66];  ///<Prime modulus p
   size_t pLen;          ///<Length of p
   const uint8_t a[66];  ///<Curve parameter a
   size_t aLen;          ///<Length of a
   const uint8_t b[66];  ///<Curve parameter b
   size_t bLen;          ///<Length of b
   const uint8_t gx[66]; ///<x-coordinate of the base point G
   size_t gxLen;         ///<Length of Gx
   const uint8_t gy[66]; ///<y-coordinate of the base point G
   size_t gyLen;         ///<Length of Gy
   const uint8_t q[66];  ///<Order of the base point G
   size_t qLen;          ///<Length of q
   uint32_t h;           ///<Cofactor h
   EcFastModAlgo mod;    ///<Fast modular reduction
} EcCurveInfo;


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
extern const uint8_t BRAINPOOLP160R1_OID[10];
extern const uint8_t BRAINPOOLP192R1_OID[10];
extern const uint8_t BRAINPOOLP224R1_OID[10];
extern const uint8_t BRAINPOOLP256R1_OID[10];
extern const uint8_t BRAINPOOLP320R1_OID[10];
extern const uint8_t BRAINPOOLP384R1_OID[10];
extern const uint8_t BRAINPOOLP512R1_OID[10];

extern const EcCurveInfo secp112r1Curve;
extern const EcCurveInfo secp112r2Curve;
extern const EcCurveInfo secp128r1Curve;
extern const EcCurveInfo secp128r2Curve;
extern const EcCurveInfo secp160k1Curve;
extern const EcCurveInfo secp160r1Curve;
extern const EcCurveInfo secp160r2Curve;
extern const EcCurveInfo secp192k1Curve;
extern const EcCurveInfo secp192r1Curve;
extern const EcCurveInfo secp224k1Curve;
extern const EcCurveInfo secp224r1Curve;
extern const EcCurveInfo secp256k1Curve;
extern const EcCurveInfo secp256r1Curve;
extern const EcCurveInfo secp384r1Curve;
extern const EcCurveInfo secp521r1Curve;
extern const EcCurveInfo brainpoolP160r1Curve;
extern const EcCurveInfo brainpoolP192r1Curve;
extern const EcCurveInfo brainpoolP224r1Curve;
extern const EcCurveInfo brainpoolP256r1Curve;
extern const EcCurveInfo brainpoolP320r1Curve;
extern const EcCurveInfo brainpoolP384r1Curve;
extern const EcCurveInfo brainpoolP512r1Curve;

//Fast modular reduction
error_t secp128r1Mod(Mpi *a, const Mpi *p);
error_t secp128r2Mod(Mpi *a, const Mpi *p);
error_t secp160k1Mod(Mpi *a, const Mpi *p);
error_t secp160r1Mod(Mpi *a, const Mpi *p);
error_t secp160r2Mod(Mpi *a, const Mpi *p);
error_t secp192k1Mod(Mpi *a, const Mpi *p);
error_t secp192r1Mod(Mpi *a, const Mpi *p);
error_t secp224k1Mod(Mpi *a, const Mpi *p);
error_t secp224r1Mod(Mpi *a, const Mpi *p);
error_t secp256k1Mod(Mpi *a, const Mpi *p);
error_t secp256r1Mod(Mpi *a, const Mpi *p);
error_t secp384r1Mod(Mpi *a, const Mpi *p);
error_t secp521r1Mod(Mpi *a, const Mpi *p);

const EcCurveInfo *ecGetCurveInfo(const uint8_t *oid, size_t length);

#endif
