/**
 * @file m460_crypto_pkc.c
 * @brief M460 public-key hardware accelerator
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
#include "m460.h"
#include "core/crypto.h"
#include "hardware/m460/m460_crypto.h"
#include "hardware/m460/m460_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/curve25519.h"
#include "ecc/curve448.h"
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

   //Retrieve the length of the operand, in words
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

   //Retrieve the length of the operand, in words
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
      //Copy the multiple-precision integer from the PKA RAM
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

   //Retrieve the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Retrieve the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Retrieve the length of the modulus, in bytes
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

   //Retrieve the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Retrieve the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Retrieve the length of the modulus, in bytes
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

   //Retrieve the length of the private key
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
 * @brief Import multiple-precision integer
 * @param[in] dest Pointer to the operand
 * @param[in] length Length of the operand, in bits
 * @param[in] a Pointer to the multiple-precision integer
 **/

void eccImportMpi(volatile uint32_t *dest, uint_t length, const Mpi *a)
{
   uint_t i;
   uint_t n;

   //Retrieve the length of the operand, in words
   length = (length + 31) / 32;

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
 * @param[in] length Length of the operand, in bits
 * @param[out] r Pointer to the multiple-precision integer
 * @return Error code
 **/

error_t eccExportMpi(volatile uint32_t *src, uint_t length, Mpi *r)
{
   error_t error;
   uint_t i;

   //Retrieve the length of the operand, in words
   length = (length + 31) / 32;

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
      //Copy the multiple-precision integer from the PKA RAM
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
   uint_t modLen;
   uint_t scalarLen;

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(&params->p);
   //Retrieve the length of the scalar, in bits
   scalarLen = mpiGetBitLength(d);

   //Check the length of the operands
   if(modLen <= 576 && scalarLen <= 576)
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&m460CryptoMutex);

      //Reset CRYPTO controller
      SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
      SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

      //Load input arguments
      eccImportMpi(CRPT->ECC_N, modLen, &params->p);
      eccImportMpi(CRPT->ECC_A, modLen, &params->a);
      eccImportMpi(CRPT->ECC_B, modLen, &params->b);
      eccImportMpi(CRPT->ECC_K, scalarLen, d);
      eccImportMpi(CRPT->ECC_X1, modLen, &s->x);
      eccImportMpi(CRPT->ECC_Y1, modLen, &s->y);
      eccImportMpi(CRPT->ECC_X2, modLen, &params->q);

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
      error = eccExportMpi(CRPT->ECC_X1, modLen, &r->x);

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = eccExportMpi(CRPT->ECC_Y1, modLen, &r->y);
      }

      //Check status code
      if(!error)
      {
         //Set the z-coordinate of the result
         error = mpiSetValue(&r->z, 1);
      }

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&m460CryptoMutex);
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
#if (X25519_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m460CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Copy the first operand
   CRPT->ECC_X1[0] = a[0];
   CRPT->ECC_X1[1] = a[1];
   CRPT->ECC_X1[2] = a[2];
   CRPT->ECC_X1[3] = a[3];
   CRPT->ECC_X1[4] = a[4];
   CRPT->ECC_X1[5] = a[5];
   CRPT->ECC_X1[6] = a[6];
   CRPT->ECC_X1[7] = a[7];

   //Copy the second operand
   CRPT->ECC_Y1[0] = b[0];
   CRPT->ECC_Y1[1] = b[1];
   CRPT->ECC_Y1[2] = b[2];
   CRPT->ECC_Y1[3] = b[3];
   CRPT->ECC_Y1[4] = b[4];
   CRPT->ECC_Y1[5] = b[5];
   CRPT->ECC_Y1[6] = b[6];
   CRPT->ECC_Y1[7] = b[7];

   //Copy the modulus
   CRPT->ECC_N[0] = 0xFFFFFFED;
   CRPT->ECC_N[1] = 0xFFFFFFFF;
   CRPT->ECC_N[2] = 0xFFFFFFFF;
   CRPT->ECC_N[3] = 0xFFFFFFFF;
   CRPT->ECC_N[4] = 0xFFFFFFFF;
   CRPT->ECC_N[5] = 0xFFFFFFFF;
   CRPT->ECC_N[6] = 0xFFFFFFFF;
   CRPT->ECC_N[7] = 0x7FFFFFFF;

   //Set up a modular multiplication operation
   CRPT->ECC_CTL = (255 << CRPT_ECC_CTL_CURVEM_Pos) | CRPT_ECC_CTL_SCAP_Msk |
      (1 << CRPT_ECC_CTL_MODOP_Pos) | (1 << CRPT_ECC_CTL_ECCOP_Pos) |
      CRPT_ECC_CTL_FSEL_Msk;

   //Clear ECC interrupt flag
   CRPT->INTSTS = CRPT_INTSTS_ECCIF_Msk;
   //Start operation
   CRPT->ECC_CTL |= CRPT_ECC_CTL_START_Msk;

   //Wait for the operation to complete
   while((CRPT->INTSTS & CRPT_INTSTS_ECCIF_Msk) == 0)
   {
   }

   //Copy the result
   r[0] = CRPT->ECC_X1[0];
   r[1] = CRPT->ECC_X1[1];
   r[2] = CRPT->ECC_X1[2];
   r[3] = CRPT->ECC_X1[3];
   r[4] = CRPT->ECC_X1[4];
   r[5] = CRPT->ECC_X1[5];
   r[6] = CRPT->ECC_X1[6];
   r[7] = CRPT->ECC_X1[7];

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m460CryptoMutex);
}

#endif
#if (X448_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve448Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m460CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Copy the first operand
   CRPT->ECC_X1[0] = a[0];
   CRPT->ECC_X1[1] = a[1];
   CRPT->ECC_X1[2] = a[2];
   CRPT->ECC_X1[3] = a[3];
   CRPT->ECC_X1[4] = a[4];
   CRPT->ECC_X1[5] = a[5];
   CRPT->ECC_X1[6] = a[6];
   CRPT->ECC_X1[7] = a[7];
   CRPT->ECC_X1[8] = a[8];
   CRPT->ECC_X1[9] = a[9];
   CRPT->ECC_X1[10] = a[10];
   CRPT->ECC_X1[11] = a[11];
   CRPT->ECC_X1[12] = a[12];
   CRPT->ECC_X1[13] = a[13];

   //Copy the second operand
   CRPT->ECC_Y1[0] = b[0];
   CRPT->ECC_Y1[1] = b[1];
   CRPT->ECC_Y1[2] = b[2];
   CRPT->ECC_Y1[3] = b[3];
   CRPT->ECC_Y1[4] = b[4];
   CRPT->ECC_Y1[5] = b[5];
   CRPT->ECC_Y1[6] = b[6];
   CRPT->ECC_Y1[7] = b[7];
   CRPT->ECC_Y1[8] = b[8];
   CRPT->ECC_Y1[9] = b[9];
   CRPT->ECC_Y1[10] = b[10];
   CRPT->ECC_Y1[11] = b[11];
   CRPT->ECC_Y1[12] = b[12];
   CRPT->ECC_Y1[13] = b[13];

   //Copy the modulus
   CRPT->ECC_N[0] = 0xFFFFFFFF;
   CRPT->ECC_N[1] = 0xFFFFFFFF;
   CRPT->ECC_N[2] = 0xFFFFFFFF;
   CRPT->ECC_N[3] = 0xFFFFFFFF;
   CRPT->ECC_N[4] = 0xFFFFFFFF;
   CRPT->ECC_N[5] = 0xFFFFFFFF;
   CRPT->ECC_N[6] = 0xFFFFFFFF;
   CRPT->ECC_N[7] = 0xFFFFFFFE;
   CRPT->ECC_N[8] = 0xFFFFFFFF;
   CRPT->ECC_N[9] = 0xFFFFFFFF;
   CRPT->ECC_N[10] = 0xFFFFFFFF;
   CRPT->ECC_N[11] = 0xFFFFFFFF;
   CRPT->ECC_N[12] = 0xFFFFFFFF;
   CRPT->ECC_N[13] = 0xFFFFFFFF;

   //Set up a modular multiplication operation
   CRPT->ECC_CTL = (448 << CRPT_ECC_CTL_CURVEM_Pos) | CRPT_ECC_CTL_SCAP_Msk |
      (1 << CRPT_ECC_CTL_MODOP_Pos) | (1 << CRPT_ECC_CTL_ECCOP_Pos) |
      CRPT_ECC_CTL_FSEL_Msk;

   //Clear ECC interrupt flag
   CRPT->INTSTS = CRPT_INTSTS_ECCIF_Msk;
   //Start operation
   CRPT->ECC_CTL |= CRPT_ECC_CTL_START_Msk;

   //Wait for the operation to complete
   while((CRPT->INTSTS & CRPT_INTSTS_ECCIF_Msk) == 0)
   {
   }

   //Copy the result
   r[0] = CRPT->ECC_X1[0];
   r[1] = CRPT->ECC_X1[1];
   r[2] = CRPT->ECC_X1[2];
   r[3] = CRPT->ECC_X1[3];
   r[4] = CRPT->ECC_X1[4];
   r[5] = CRPT->ECC_X1[5];
   r[6] = CRPT->ECC_X1[6];
   r[7] = CRPT->ECC_X1[7];
   r[8] = CRPT->ECC_X1[8];
   r[9] = CRPT->ECC_X1[9];
   r[10] = CRPT->ECC_X1[10];
   r[11] = CRPT->ECC_X1[11];
   r[12] = CRPT->ECC_X1[12];
   r[13] = CRPT->ECC_X1[13];

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m460CryptoMutex);
}

#endif
#endif
