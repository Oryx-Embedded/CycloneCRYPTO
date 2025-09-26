/**
 * @file xdrbg.h
 * @brief XDRBG pseudorandom number generator
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
 * @version 2.5.4
 **/

#ifndef _XDRBG_H
#define _XDRBG_H

//Dependencies
#include "core/crypto.h"
#include "xof/xof_algorithms.h"

//Maximum length of the additional data
#define XDRBG_MAX_ALPHA_LEN 84
//Maximum size of the internal state
#define XDRBG_MAX_V_SIZE 64

//Common interface for PRNG algorithms
#define XDRBG_PRNG_ALGO (&xdrbgPrngAlgo)

//Encode function
#define XDRBG_ENCODE(alphaLen, n) ((n * 85) + alphaLen)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief XDRBG PRNG context
 **/

typedef struct
{
   OsMutex mutex;               ///<Mutex preventing simultaneous access to the PRNG state
   const XofAlgo *xofAlgo;      ///<XOF algorithm
   XofContext xofContext;       ///<XOF context
   size_t securityStrength;     ///<Security strength
   size_t maxOutputLen;         ///<Maximum output length
   uint8_t v[XDRBG_MAX_V_SIZE]; ///<Internal state V
   uint64_t reseedCounter;      ///<Reseed counter
} XdrbgContext;


//XDRBG related constants
extern const PrngAlgo xdrbgPrngAlgo;

//XDRBG related functions
error_t xdrbgInit(XdrbgContext *context, const XofAlgo *xofAlgo);

error_t xdrbgSeed(XdrbgContext *context, const uint8_t *seed, size_t length);

error_t xdrbgSeedEx(XdrbgContext *context, const uint8_t *seed, size_t seedLen,
   const uint8_t *alpha, size_t alphaLen);

error_t xdrbgReseed(XdrbgContext *context, const uint8_t *seed, size_t length);

error_t xdrbgReseedEx(XdrbgContext *context, const uint8_t *seed,
   size_t seedLen, const uint8_t *alpha, size_t alphaLen);

error_t xdrbgGenerate(XdrbgContext *context, uint8_t *output, size_t length);

error_t xdrbgGenerateEx(XdrbgContext *context, const uint8_t *alpha,
   size_t alphaLen, uint8_t *output, size_t outputLen);

void xdrbgDeinit(XdrbgContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
