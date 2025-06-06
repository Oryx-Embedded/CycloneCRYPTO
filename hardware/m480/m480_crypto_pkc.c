/**
 * @file m480_crypto_pkc.c
 * @brief M480 public-key hardware accelerator
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
#include "m480.h"
#include "core/crypto.h"
#include "hardware/m480/m480_crypto.h"
#include "hardware/m480/m480_crypto_pkc.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (M480_CRYPTO_PKC_SUPPORT == ENABLED)
#if (EC_SUPPORT == ENABLED)

/**
 * @brief Import scalar
 * @param[in] dest Pointer to the operand
 * @param[in] length Length of the operand, in bits
 * @param[in] src Pointer to the scalar
 **/

void eccImportScalar(volatile uint32_t *dest, uint_t length, const uint32_t *src)
{
   uint_t i;

   //Get the length of the operand, in words
   length = (length + 31) / 32;

   //Copy the scalar to the CRYPTO peripheral
   for(i = 0; i < length; i++)
   {
      dest[i] = src[i];
   }
}


/**
 * @brief Export scalar
 * @param[in] src Pointer to the operand
 * @param[in] length Length of the operand, in bits
 * @param[out] dest Pointer to the scalar
 **/

void eccExportScalar(volatile uint32_t *src, uint_t length, uint32_t *dest)
{
   uint_t i;

   //Get the length of the operand, in words
   length = (length + 31) / 32;

   //Copy the scalar from the CRYPTO peripheral
   for(i = 0; i < length; i++)
   {
      dest[i] = src[i];
   }
}


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
   uint_t modLen;
   uint_t orderLen;

   //Get the length of the modulus, in bits
   modLen = curve->fieldSize;
   //Get the length of the order, in bits
   orderLen = curve->orderSize;

   //Check the length of the operands
   if(modLen <= 576 && orderLen <= 576)
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&m480CryptoMutex);

      //Reset CRYPTO controller
      SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
      SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

      //Load input arguments
      eccImportScalar(CRPT->ECC_N, modLen, curve->p);
      eccImportScalar(CRPT->ECC_A, modLen, curve->a);
      eccImportScalar(CRPT->ECC_B, modLen, curve->b);
      eccImportScalar(CRPT->ECC_K, orderLen, d);
      eccImportScalar(CRPT->ECC_X1, modLen, s->x);
      eccImportScalar(CRPT->ECC_Y1, modLen, s->y);
      eccImportScalar(CRPT->ECC_X2, orderLen, curve->q);

      //Set up a point multiplication operation
      CRPT->ECC_CTL = (modLen << CRPT_ECC_CTL_CURVEM_Pos) |
         (0 << CRPT_ECC_CTL_ECCOP_Pos) | CRPT_ECC_CTL_FSEL_Msk;

      //Clear ECC interrupt flag
      CRPT->INTSTS = CRPT_INTSTS_ECCIF_Msk;
      //Enable ECC interrupt
      CRPT->INTEN = CRPT_INTEN_ECCIEN_Msk;
      //Start operation
      CRPT->ECC_CTL |= CRPT_ECC_CTL_START_Msk;

      //Wait for the operation to complete
      while((CRPT->INTSTS & CRPT_INTSTS_ECCIF_Msk) == 0)
      {
      }

      //Copy the x-coordinate of the result
      ecScalarSetInt(r->x, 0, EC_MAX_MODULUS_SIZE);
      eccExportScalar(CRPT->ECC_X1, modLen, r->x);

      //Copy the y-coordinate of the result
      ecScalarSetInt(r->y, 0, EC_MAX_MODULUS_SIZE);
      eccExportScalar(CRPT->ECC_Y1, modLen, r->y);

      //Set the z-coordinate of the result
      ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&m480CryptoMutex);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

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
#endif
