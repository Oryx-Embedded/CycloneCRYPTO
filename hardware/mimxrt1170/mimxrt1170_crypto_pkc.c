/**
 * @file mimxrt1170_crypto_pkc.c
 * @brief i.MX RT1170 public-key hardware accelerator
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
#include "fsl_caam.h"
#include "core/crypto.h"
#include "hardware/mimxrt1170/mimxrt1170_crypto.h"
#include "hardware/mimxrt1170/mimxrt1170_crypto_pkc.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1170_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
PkhaArgs pkhaArgs;
PkhaEccArgs pkhaEccArgs;

#if (MPI_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = A * B mod P
 * @param[in] a The first operand A
 * @param[in] b The second operand B
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiMulMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p)
{
   error_t error;
   status_t status;
   size_t aLen;
   size_t bLen;
   size_t modLen;
   size_t resultLen;
   caam_handle_t caamHandle;
   Mpi ta;
   Mpi tb;

   //Initialize multiple precision integers
   mpiInit(&ta);
   mpiInit(&tb);

   //Get the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if(modLen <= 512)
   {
      //Reduce the first operand
      error = mpiMod(&ta, a, p);

      //Check status code
      if(!error)
      {
         //Reduce the second operand
         error = mpiMod(&tb, b, p);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the first operand, in bytes
         aLen = mpiGetByteLength(&ta);
         //Get the length of the second operand, in bytes
         bLen = mpiGetByteLength(&tb);

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1170CryptoMutex);

         //Copy first operand
         mpiWriteRaw(&ta, pkhaArgs.a, aLen);
         //Copy second operand
         mpiWriteRaw(&tb, pkhaArgs.b, bLen);
         //Copy modulus
         mpiWriteRaw(p, pkhaArgs.p, modLen);

         //Perform modular multiplication
         status = CAAM_PKHA_ModMul(CAAM, &caamHandle, pkhaArgs.a, aLen,
            pkhaArgs.b, bLen, pkhaArgs.p, modLen, pkhaArgs.r, &resultLen,
            kCAAM_PKHA_IntegerArith, kCAAM_PKHA_NormalValue,
            kCAAM_PKHA_NormalValue, kCAAM_PKHA_TimingEqualized);

         //Check status code
         if(status == kStatus_Success)
         {
            //Copy resulting integer
            error = mpiReadRaw(r, pkhaArgs.r, resultLen);
         }
         else
         {
            //Report an error
            error = ERROR_FAILURE;
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1170CryptoMutex);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release multiple precision integers
   mpiFree(&ta);
   mpiFree(&tb);

   //Return status code
   return error;
}


/**
 * @brief Modular exponentiation
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t mpiExpMod(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   status_t status;
   size_t scalarLen;
   size_t expLen;
   size_t modLen;
   size_t resultLen;
   caam_handle_t caamHandle;

   //Get the length of the exponent, in bytes
   expLen = mpiGetByteLength(e);
   //Get the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if(modLen > 0 && modLen <= 512 && expLen > 0 && expLen <= 512)
   {
      //Reduce the integer first
      error = mpiMod(r, a, p);

      //Check status code
      if(!error)
      {
         //Get the length of the integer, in bytes
         scalarLen = mpiGetByteLength(r);

         //Set CAAM job ring
         caamHandle.jobRing = kCAAM_JobRing0;

         //Acquire exclusive access to the CAAM module
         osAcquireMutex(&mimxrt1170CryptoMutex);

         //Copy scalar
         mpiWriteRaw(r, pkhaArgs.a, scalarLen);
         //Copy exponent
         mpiWriteRaw(e, pkhaArgs.e, expLen);
         //Copy modulus
         mpiWriteRaw(p, pkhaArgs.p, modLen);

         //Perform modular exponentiation
         status = CAAM_PKHA_ModExp(CAAM, &caamHandle, pkhaArgs.a, scalarLen,
            pkhaArgs.p, modLen, pkhaArgs.e, expLen, pkhaArgs.r, &resultLen,
            kCAAM_PKHA_IntegerArith, kCAAM_PKHA_NormalValue,
            kCAAM_PKHA_TimingEqualized);

         //Check status code
         if(status == kStatus_Success)
         {
            //Copy resulting integer
            error = mpiReadRaw(r, pkhaArgs.r, resultLen);
         }
         else
         {
            //Report an error
            error = ERROR_FAILURE;
         }

         //Release exclusive access to the CAAM module
         osReleaseMutex(&mimxrt1170CryptoMutex);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
#if (EC_SUPPORT == ENABLED)

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
   status_t status;
   size_t modLen;
   size_t orderLen;
   caam_handle_t caamHandle;
   caam_pkha_ecc_point_t input;
   caam_pkha_ecc_point_t output;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;

   //Check the length of the operands
   if(modLen <= 66 && orderLen <= 66)
   {
      //Set CAAM job ring
      caamHandle.jobRing = kCAAM_JobRing0;

      //Acquire exclusive access to the CAAM module
      osAcquireMutex(&mimxrt1170CryptoMutex);

      //Copy domain parameters
      ecScalarExport(curve->p, (modLen + 3) / 4, pkhaEccArgs.p, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->a, (modLen + 3) / 4, pkhaEccArgs.a, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->b, (modLen + 3) / 4, pkhaEccArgs.b, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Copy scalar
      ecScalarExport(d, (orderLen + 3) / 4, pkhaEccArgs.d, orderLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Copy input point
      ecScalarExport(s->x, (modLen + 3) / 4, pkhaEccArgs.gx, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(s->y, (modLen + 3) / 4, pkhaEccArgs.gy, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      input.X = pkhaEccArgs.gx;
      input.Y = pkhaEccArgs.gy;

      //Specify the buffer where to store the output point
      output.X = pkhaEccArgs.qx;
      output.Y = pkhaEccArgs.qy;

      //Perform scalar multiplication
      status = CAAM_PKHA_ECC_PointMul(CAAM, &caamHandle, &input, pkhaEccArgs.d,
         orderLen, pkhaEccArgs.p, NULL, pkhaEccArgs.a, pkhaEccArgs.b,
         modLen, kCAAM_PKHA_TimingEqualized, kCAAM_PKHA_IntegerArith, &output);

      //Check status code
      if(status == kStatus_Success)
      {
         //Copy the x-coordinate of the result
         error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE, pkhaEccArgs.qx,
            modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Copy the y-coordinate of the result
            error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE, pkhaEccArgs.qy,
               modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Set the z-coordinate of the result
            ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);
         }
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the CAAM module
      osReleaseMutex(&mimxrt1170CryptoMutex);
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
