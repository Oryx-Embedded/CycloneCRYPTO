/**
 * @file m460_crypto_pkc.c
 * @brief M460 public-key hardware accelerator
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
#include "m460.h"
#include "core/crypto.h"
#include "hardware/m460/m460_crypto.h"
#include "hardware/m460/m460_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (M460_CRYPTO_PKC_SUPPORT == ENABLED)
#if (MPI_SUPPORT == ENABLED)

//Global variables
static M460RsaArgs rsaArgs;


/**
 * @brief Import multiple-precision integer
 * @param[in] dest Pointer to the operand
 * @param[in] length Length of the operand, in bytes
 * @param[in] a Pointer to the multiple-precision integer
 **/

void rsaImportMpi(uint32_t *dest, uint_t length, const Mpi *a)
{
   uint_t i;
   uint_t n;

   //Get the length of the operand, in words
   length = (length + 3) / 4;

   //Get the actual length of the multiple-precision integer, in words
   n = mpiGetLength(a);

   //Copy the multiple-precision integer to the CRYPTO peripheral
   for(i = 0; i < n && i < length; i++)
   {
      dest[i] = a->data[i];
   }

   //Pad the operand with zeroes
   for(; i < length; i++)
   {
      dest[i] = 0;
   }
}


/**
 * @brief Export multiple-precision integer
 * @param[in] src Pointer to the operand
 * @param[in] length Length of the operand, in bytes
 * @param[out] r Pointer to the multiple-precision integer
 * @return Error code
 **/

error_t rsaExportMpi(uint32_t *src, uint_t length, Mpi *r)
{
   error_t error;
   uint_t i;

   //Get the length of the operand, in words
   length = (length + 3) / 4;

   //Skip trailing zeroes
   while(length > 0 && src[length - 1] == 0)
   {
      length--;
   }

   //Ajust the size of the multiple precision integer
   error = mpiGrow(r, length);

   //Check status code
   if(!error)
   {
      //Copy the multiple-precision integer from the CRYPTO peripheral
      for(i = 0; i < length; i++)
      {
         r->data[i] = src[i];
      }

      //Pad the resulting value with zeroes
      for(; i < r->size; i++)
      {
         r->data[i] = 0;
      }

      //Set the sign
      r->sign = 1;
   }

   //Return status code
   return error;
}


/**
 * @brief Modular exponentiation (fast calculation)
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t mpiExpModFast(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   size_t aLen;
   size_t eLen;
   size_t pLen;

   //Get the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Get the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Get the length of the modulus, in bytes
   pLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if((aLen <= 128 && eLen <= 128 && pLen == 128) ||
      (aLen <= 256 && eLen <= 256 && pLen == 256) ||
      (aLen <= 384 && eLen <= 384 && pLen == 384) ||
      (aLen <= 512 && eLen <= 512 && pLen == 512))
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&m460CryptoMutex);

      //Reset CRYPTO controller
      SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
      SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

      //Copy the operands
      rsaImportMpi(rsaArgs.m, pLen, a);
      rsaImportMpi(rsaArgs.n, pLen, p);
      rsaImportMpi(rsaArgs.e, pLen, e);

      //Program DMA source address to register CRYPTO_RSA_SADDR0-2
      CRPT->RSA_SADDR[0] = (uint32_t) rsaArgs.m;
      CRPT->RSA_SADDR[1] = (uint32_t) rsaArgs.n;
      CRPT->RSA_SADDR[2] = (uint32_t) rsaArgs.e;

      //Program DMA destination address to register CRYPTO_RSA_DADDR
      CRPT->RSA_DADDR = (uint32_t) rsaArgs.r;

      //Select appropriate key length
      CRPT->RSA_CTL = (((pLen / 128) - 1) << CRPT_RSA_CTL_KEYLENG_Pos);

      //Clear RSA interrupt flag
      CRPT->INTSTS = CRPT_INTSTS_RSAIF_Msk;
      //Start operation
      CRPT->RSA_CTL |= CRPT_RSA_CTL_START_Msk;

      //Wait for the operation to complete
      while((CRPT->INTSTS & CRPT_INTSTS_RSAIF_Msk) == 0)
      {
      }

      //Read output data
      rsaExportMpi(rsaArgs.r, pLen, r);

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&m460CryptoMutex);

      //Successful operation
      error = NO_ERROR;
   }
   else
   {
      //Perform modular exponentiation (r = a ^ e mod p)
      error = mpiExpMod(r, a, e, p);
   }

   //Return status code
   return error;
}


/**
 * @brief Modular exponentiation (regular calculation)
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t mpiExpModRegular(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   size_t aLen;
   size_t eLen;
   size_t pLen;

   //Get the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Get the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Get the length of the modulus, in bytes
   pLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if((pLen == 128 && aLen <= 128 && eLen <= 128) ||
      (pLen == 256 && aLen <= 256 && eLen <= 256) ||
      (pLen == 384 && aLen <= 384 && eLen <= 384) ||
      (pLen == 512 && aLen <= 512 && eLen <= 512))
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&m460CryptoMutex);

      //Reset CRYPTO controller
      SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
      SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

      //Copy the operands
      rsaImportMpi(rsaArgs.m, pLen, a);
      rsaImportMpi(rsaArgs.n, pLen, p);
      rsaImportMpi(rsaArgs.e, pLen, e);

      //Program DMA source address to register CRYPTO_RSA_SADDR0-2
      CRPT->RSA_SADDR[0] = (uint32_t) rsaArgs.m;
      CRPT->RSA_SADDR[1] = (uint32_t) rsaArgs.n;
      CRPT->RSA_SADDR[2] = (uint32_t) rsaArgs.e;

      //Program DMA destination address to register CRYPTO_RSA_DADDR
      CRPT->RSA_DADDR = (uint32_t) rsaArgs.r;

      //Select appropriate key length
      CRPT->RSA_CTL = (((pLen / 128) - 1) << CRPT_RSA_CTL_KEYLENG_Pos);

      //Clear RSA interrupt flag
      CRPT->INTSTS = CRPT_INTSTS_RSAIF_Msk;
      //Start operation
      CRPT->RSA_CTL |= CRPT_RSA_CTL_START_Msk;

      //Wait for the operation to complete
      while((CRPT->INTSTS & CRPT_INTSTS_RSAIF_Msk) == 0)
      {
      }

      //Read output data
      rsaExportMpi(rsaArgs.r, pLen, r);

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&m460CryptoMutex);

      //Successful operation
      error = NO_ERROR;
   }
   else
   {
      //Perform modular exponentiation (r = a ^ e mod p)
      error = mpiExpMod(r, a, e, p);
   }

   //Return status code
   return error;
}

#endif
#if (RSA_SUPPORT == ENABLED)

/**
 * @brief RSA decryption primitive
 *
 * The RSA decryption primitive recovers the message representative from
 * the ciphertext representative under the control of a private key
 *
 * @param[in] key RSA private key
 * @param[in] c Ciphertext representative
 * @param[out] m Message representative
 * @return Error code
 **/

error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;
   size_t nLen;
   size_t dLen;
   size_t pLen;
   size_t qLen;
   size_t dpLen;
   size_t dqLen;
   size_t qinvLen;

   //Get the length of the private key
   nLen = mpiGetByteLength(&key->n);
   dLen = mpiGetByteLength(&key->d);
   pLen = mpiGetByteLength(&key->p);
   qLen = mpiGetByteLength(&key->q);
   dpLen = mpiGetByteLength(&key->dp);
   dqLen = mpiGetByteLength(&key->dq);
   qinvLen = mpiGetByteLength(&key->qinv);

   //Sanity check
   if(nLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The ciphertext representative c shall be between 0 and n - 1
   if(mpiCompInt(c, 0) < 0 || mpiComp(c, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Check the length of the private key
   if((nLen == 128 && dLen <= 128) || (nLen == 384 && dLen <= 384))
   {
      //Let m = c ^ d mod n
      error = mpiExpModRegular(m, c, &key->d, &key->n);
   }
   else if(nLen > 0 && pLen > 0 && qLen > 0 && dpLen > 0 && dqLen > 0 &&
      qinvLen > 0)
   {
      Mpi m1;
      Mpi m2;
      Mpi h;

      //Initialize multiple-precision integers
      mpiInit(&m1);
      mpiInit(&m2);
      mpiInit(&h);

      //Compute m1 = c ^ dP mod p
      error = mpiMod(&m1, c, &key->p);

      if(!error)
      {
         error = mpiExpModRegular(&m1, &m1, &key->dp, &key->p);
      }

      //Compute m2 = c ^ dQ mod q
      if(!error)
      {
         error = mpiMod(&m2, c, &key->q);
      }

      if(!error)
      {
         error = mpiExpModRegular(&m2, &m2, &key->dq, &key->q);
      }

      //Let h = (m1 - m2) * qInv mod p
      if(!error)
      {
         error = mpiSub(&h, &m1, &m2);
      }

      if(!error)
      {
         error = mpiMulMod(&h, &h, &key->qinv, &key->p);
      }

      //Let m = m2 + q * h
      if(!error)
      {
         error = mpiMul(m, &key->q, &h);
      }

      if(!error)
      {
         error = mpiAdd(m, m, &m2);
      }

      //Free previously allocated memory
      mpiFree(&m1);
      mpiFree(&m2);
      mpiFree(&h);
   }
   else if(nLen > 0 && dLen > 0)
   {
      //Let m = c ^ d mod n
      error = mpiExpModRegular(m, c, &key->d, &key->n);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}

#endif
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
      osAcquireMutex(&m460CryptoMutex);

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
         CRPT_ECC_CTL_SCAP_Msk | (0 << CRPT_ECC_CTL_ECCOP_Pos) |
         CRPT_ECC_CTL_FSEL_Msk;

      //Clear ECC interrupt flag
      CRPT->INTSTS = CRPT_INTSTS_ECCIF_Msk;
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
      osReleaseMutex(&m460CryptoMutex);

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
