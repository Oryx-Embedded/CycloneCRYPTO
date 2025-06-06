/**
 * @file lpc55s6x_crypto_pkc.c
 * @brief LPC55S6x public-key hardware accelerator
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
#include "fsl_device_registers.h"
#include "fsl_casper.h"
#include "core/crypto.h"
#include "hardware/lpc55s6x/lpc55s6x_crypto.h"
#include "hardware/lpc55s6x/lpc55s6x_crypto_pkc.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (LPC55S6X_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
static Lpc55s6xEcArgs ecArgs;


/**
 * @brief Scalar multiplication (fast calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMulFast(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s)
{
   //Compute R = d.S
   return ecMulRegular(curve, r, d, s);
}


/**
 * @brief Scalar multiplication (regular calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < q
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMulRegular(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s)
{
   error_t error;
   size_t n;
   uint_t modLen;
   uint_t orderLen;

   //Get the length of the modulus, in words
   modLen = (curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   orderLen = (curve->orderSize + 31) / 32;

   //Initialize status code
   error = NO_ERROR;

   //Check elliptic curve parameters
   if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      n = 32;
   }
   else if(osStrcmp(curve->name, "secp384r1") == 0)
   {
      n = 48;
   }
   else if(osStrcmp(curve->name, "secp521r1") == 0)
   {
      n = 72;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Acquire exclusive access to the CASPER module
   osAcquireMutex(&lpc55s6xCryptoMutex);

   //Set scalar value
   ecScalarExport(d, orderLen, (uint8_t *) ecArgs.d, n,
      EC_SCALAR_FORMAT_LITTLE_ENDIAN);

   //Set input point
   ecScalarExport(s->x, modLen, (uint8_t *) ecArgs.sx, n,
      EC_SCALAR_FORMAT_LITTLE_ENDIAN);

   ecScalarExport(s->y, modLen, (uint8_t *) ecArgs.sy, n,
      EC_SCALAR_FORMAT_LITTLE_ENDIAN);

   //Initialize curve parameters in CASPER memory
   if(n == 32)
   {
      CASPER_ecc_init(kCASPER_ECC_P256);
   }
   else if(n == 48)
   {
      CASPER_ecc_init(kCASPER_ECC_P384);
   }
   else
   {
      CASPER_ecc_init(kCASPER_ECC_P521);
   }

   //Perform scalar multiplication
   if(n == 32)
   {
      CASPER_ECC_SECP256R1_Mul(CASPER, ecArgs.rx, ecArgs.ry, ecArgs.sx,
         ecArgs.sy, ecArgs.d);
   }
   else if(n == 48)
   {
      CASPER_ECC_SECP384R1_Mul(CASPER, ecArgs.rx, ecArgs.ry, ecArgs.sx,
         ecArgs.sy, ecArgs.d);
   }
   else
   {
      CASPER_ECC_SECP521R1_Mul(CASPER, ecArgs.rx, ecArgs.ry, ecArgs.sx,
         ecArgs.sy, ecArgs.d);
   }

   //Copy the x-coordinate of the result
   error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE, (uint8_t *) ecArgs.rx, n,
      EC_SCALAR_FORMAT_LITTLE_ENDIAN);

   //Check status code
   if(!error)
   {
      //Copy the y-coordinate of the result
      error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE, (uint8_t *) ecArgs.ry,
         n, EC_SCALAR_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Set the z-coordinate of the result
      ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);
   }

   //Release exclusive access to the CASPER module
   osReleaseMutex(&lpc55s6xCryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief Twin multiplication
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d0.S + d1.T
 * @param[in] d0 An integer d such as 0 <= d0 < p
 * @param[in] s EC point
 * @param[in] d1 An integer d such as 0 <= d1 < p
 * @param[in] t EC point
 * @return Error code
 **/

error_t ecTwinMul(const EcCurve *curve, EcPoint3 *r, const uint32_t *d0,
   const EcPoint3 *s, const uint32_t *d1, const EcPoint3 *t)
{
   error_t error;
   EcPoint3 u;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   EcState *state;
#else
   EcState state[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(EcState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(EcState));
   //Save elliptic curve parameters
   state->curve = curve;

   //Compute d0.S
   error = ecMulFast(curve, r, d0, s);

   //Check status code
   if(!error)
   {
      //Compute d1.T
      error = ecMulFast(curve, &u, d1, t);
   }

   //Check status code
   if(!error)
   {
      //Compute d0.S + d1.T
      ecFullAdd(state, r, r, &u);
   }

   //Return status code
   return error;
}

#endif
