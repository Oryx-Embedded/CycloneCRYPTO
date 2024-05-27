/**
 * @file lpc55s6x_crypto_pkc.c
 * @brief LPC55S6x public-key hardware accelerator
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.2
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
#include "debug.h"

//Check crypto library configuration
#if (LPC55S6X_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
static Lpc55s6xEcArgs ecArgs;


/**
 * @brief Scalar multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMult(const EcDomainParameters *params, EcPoint *r, const Mpi *d,
   const EcPoint *s)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check elliptic curve parameters
   if(!osStrcmp(params->name, "secp256r1"))
   {
      n = 32;
   }
   else if(!osStrcmp(params->name, "secp384r1"))
   {
      n = 48;
   }
   else if(!osStrcmp(params->name, "secp521r1"))
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
   mpiExport(d, (uint8_t *) ecArgs.d, n, MPI_FORMAT_LITTLE_ENDIAN);

   //Set input point
   mpiExport(&s->x, (uint8_t *) ecArgs.sx, n, MPI_FORMAT_LITTLE_ENDIAN);
   mpiExport(&s->y, (uint8_t *) ecArgs.sy, n, MPI_FORMAT_LITTLE_ENDIAN);

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
   error = mpiImport(&r->x, (uint8_t *) ecArgs.rx, n,
      MPI_FORMAT_LITTLE_ENDIAN);

   //Check status code
   if(!error)
   {
      //Copy the y-coordinate of the result
      error = mpiImport(&r->y, (uint8_t *) ecArgs.ry, n,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Set the z-coordinate of the result
      error = mpiSetValue(&r->z, 1);
   }

   //Release exclusive access to the CASPER module
   osReleaseMutex(&lpc55s6xCryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief Twin multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = d0.S + d1.T
 * @param[in] d0 An integer d such as 0 <= d0 < p
 * @param[in] s EC point
 * @param[in] d1 An integer d such as 0 <= d1 < p
 * @param[in] t EC point
 * @return Error code
 **/

error_t ecTwinMult(const EcDomainParameters *params, EcPoint *r,
   const Mpi *d0, const EcPoint *s, const Mpi *d1, const EcPoint *t)
{
   error_t error;
   EcPoint u;

   //Initialize EC point
   ecInit(&u);

   //Compute d0.S
   error = ecMult(params, r, d0, s);

   //Check status code
   if(!error)
   {
      //Compute d1.T
      error = ecMult(params, &u, d1, t);
   }

   //Check status code
   if(!error)
   {
      //Compute d0.S + d1.T
      error = ecAdd(params, r, r, &u);
   }

   //Release EC point
   ecFree(&u);

   //Return status code
   return error;
}

#endif
