/**
 * @file pic32cx_mt_crypto_pkc.c
 * @brief PIC32CX MTC/MTG/MTSH public-key hardware accelerator (CPKCC)
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
#include "pic32c.h"
#include "cpkcc/CryptoLib_cf.h"
#include "cpkcc/CryptoLib_JumpTable_Addr_pb.h"
#include "core/crypto.h"
#include "hardware/pic32cx_mt/pic32cx_mt_crypto.h"
#include "hardware/pic32cx_mt/pic32cx_mt_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/ecdsa.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (PIC32CX_MT_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
PCPKCL_PARAM pvCPKCLParam;
CPKCL_PARAM CPKCLParam;


/**
 * @brief Initialize CPKCC module
 **/

error_t cpkccInit(void)
{
   uint32_t temp;

   //Enable CPKCC peripheral clock
   PMC_REGS->PMC_PCR = PMC_PCR_PID(ID_CPKCC);
   temp = PMC_REGS->PMC_PCR;
   PMC_REGS->PMC_PCR = temp | PMC_PCR_CMD_Msk | PMC_PCR_EN_Msk;

   //Delay
   sleep(10);

   //Clear CPKCLParam structure
   osMemset(&CPKCLParam, 0, sizeof(CPKCL_PARAM));
   pvCPKCLParam = &CPKCLParam;

   //Initialize CPKCC
   vCPKCL_Process(SelfTest, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) != CPKCL_OK)
      return ERROR_FAILURE;

   //Check version number
   if(pvCPKCLParam->P.CPKCL_SelfTest_s.u4Version != CPKCL_VERSION)
      return ERROR_FAILURE;

   //The return values from the SelfTest service must be compared against
   //known values mentioned in the service description
   if(pvCPKCLParam->P.CPKCL_SelfTest_s.u4CheckNum1 != 0x6E70DDD2)
      return ERROR_FAILURE;

   if(pvCPKCLParam->P.CPKCL_SelfTest_s.u4CheckNum2 != 0x25C8D64F)
      return ERROR_FAILURE;

   if(pvCPKCLParam->P.CPKCL_SelfTest_s.u1Step != 0x03)
      return ERROR_FAILURE;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Import byte array
 * @param[in,out] dest Pointer to the crypto memory
 * @param[in] src Pointer to the byte array
 * @param[in] srcLen Length of the array to be copied
 * @param[in] totalLen Desired length of the area, in bytes
 * @return Pointer to the initialized area
 **/

uint8_t *cpkccImportArray(uint8_t **dest, const uint8_t *src, size_t srcLen,
   size_t totalLen)
{
   size_t i;
   uint8_t *p;

   //Point to the crypto memory
   p = *dest;

   //Copy the byte array to the crypto memory
   for(i = 0; i < srcLen; i++)
   {
      p[i] = src[srcLen - 1 - i];
   }

   //Pad the data with zeroes
   while(i < totalLen)
   {
      p[i++] = 0;
   }

   //Advance data pointer
   *dest = p + i;

   //Return a pointer to the initialized area
   return p;
}


/**
 * @brief Import scalar
 * @param[in,out] dest Pointer to the crypto memory
 * @param[in] src Pointer to the scalar
 * @param[in] totalLen Desired length of the area, in bytes
 * @return Pointer to the initialized area
 **/

uint8_t *cpkccImportScalar(uint8_t **dest, const uint32_t *src, size_t totalLen)
{
   uint8_t *p;

   //Point to the crypto memory
   p = *dest;

   //Copy the scalar to the crypto memory
   ecScalarExport(src, (totalLen - 1) / 4, p, totalLen, EC_SCALAR_FORMAT_LITTLE_ENDIAN);

   //Advance data pointer
   *dest = p + totalLen;

   //Return a pointer to the initialized area
   return p;
}


/**
 * @brief Import multiple-precision integer
 * @param[in,out] dest Pointer to the crypto memory
 * @param[in] src Pointer to the multiple-precision integer
 * @param[in] totalLen Desired length of the area, in bytes
 * @return Pointer to the initialized area
 **/

uint8_t *cpkccImportMpi(uint8_t **dest, const Mpi *src, size_t totalLen)
{
   uint8_t *p;

   //Point to the crypto memory
   p = *dest;

   //Copy the multiple-precision integer to the crypto memory
   mpiExport(src, p, totalLen, MPI_FORMAT_LITTLE_ENDIAN);

   //Advance data pointer
   *dest = p + totalLen;

   //Return a pointer to the initialized area
   return p;
}


/**
 * @brief Initialize workspace area
 * @param[in,out] dest Pointer to the crypto memory
 * @param[in] totalLen Desired length of the area, in bytes
 * @return Pointer to the initialized area
 **/

uint8_t *cpkccWorkspace(uint8_t **dest, size_t totalLen)
{
   size_t i;
   uint8_t *p;

   //Point to the crypto memory
   p = *dest;

   //Initialize workspace area
   for(i = 0; i < totalLen; i++)
   {
      p[i] = 0;
   }

   //Advance data pointer
   *dest = p + i;

   //Return a pointer to the initialized area
   return p;
}


#if (MPI_SUPPORT == ENABLED)

/**
 * @brief Multiple precision multiplication
 * @param[out] r Resulting integer R = A * B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiMul(Mpi *r, const Mpi *a, const Mpi *b)
{
   error_t error;
   size_t m;
   size_t n;
   uint8_t *pos;
   PukccFmultParams params = {0};

   //Get the length of the input integer, in bytes
   m = mpiGetByteLength(a);
   m = (m + 3U) & ~3U;

   //Get the length of the modulus, in bytes
   n = mpiGetByteLength(b);
   n = (n + 3U) & ~3U;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy input integer X
   params.x = cpkccImportMpi(&pos, a, m);
   //Copy input integer Y
   params.y = cpkccImportMpi(&pos, b, n);

   //Unused parameters
   params.z = 0;
   params.mod = 0;
   params.cns = 0;

   //Initialize output integer R
   params.r = cpkccWorkspace(&pos, m + n);

   //Set Fmult service parameters
   CPKCL(u2Option) = SET_MULTIPLIEROPTION(CPKCL_FMULT_ONLY) |
      SET_CARRYOPTION(CARRY_NONE);
   CPKCL(Specific).CarryIn = 0;
   CPKCL(Specific).Gf2n = 0;
   CPKCL_Fmult(u2ModLength) = 0;
   CPKCL_Fmult(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
   CPKCL_Fmult(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_Fmult(u2XLength) = m;
   CPKCL_Fmult(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);
   CPKCL_Fmult(u2YLength) = n;
   CPKCL_Fmult(nu1YBase) = CPKCC_FAR_TO_NEAR(params.y);
   CPKCL_Fmult(nu1ZBase) = CPKCC_FAR_TO_NEAR(params.z);
   CPKCL_Fmult(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);

   //Perform multiplication
   vCPKCL_Process(Fmult, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //If FMult is without reduction, R is filled with the final result
      error = mpiImport(r, params.r, m + n, MPI_FORMAT_LITTLE_ENDIAN);

      //Check status code
      if(!error)
      {
         //Set the sign of the result
         r->sign = (a->sign == b->sign) ? 1 : -1;
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief Modulo operation
 * @param[out] r Resulting integer R = A mod P
 * @param[in] a The multiple precision integer to be reduced
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiMod2(Mpi *r, const Mpi *a, const Mpi *p)
{
   error_t error;
   size_t n;
   size_t modLen;
   uint8_t *pos;
   PukccRedModParams params = {0};

   //Get the length of the input integer, in bytes
   n = mpiGetByteLength(a);

   //Get the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);
   modLen = (modLen + 3U) & ~3U;

   //Check the length of the input integer
   if(n > (2 * modLen + 4))
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = cpkccImportMpi(&pos, p, modLen + 4);
   //Initialize workspace CNS
   params.cns = cpkccWorkspace(&pos, 68);
   //Initialize output integer R
   params.r = cpkccWorkspace(&pos, modLen + 4);
   //Copy input integer X
   params.x = cpkccImportMpi(&pos, a, 2 * modLen + 8);

   //Set RedMod service parameters
   CPKCL(u2Option) = CPKCL_REDMOD_REDUCTION | CPKCL_REDMOD_USING_DIVISION;
   CPKCL(Specific).CarryIn = 0;
   CPKCL(Specific).Gf2n = 0;
   CPKCL_RedMod(u2ModLength) = modLen;
   CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
   CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
   CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vCPKCL_Process(RedMod, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //If FMult is without reduction, R is filled with the final result
      error = mpiImport(r, params.r, modLen, MPI_FORMAT_LITTLE_ENDIAN);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief Modular inverse
 * @param[out] r Resulting integer R = A^-1 mod P
 * @param[in] a The multiple precision integer A
 * @param[in] p The modulus P
 * @return Error code
 **/

error_t mpiInvMod(Mpi *r, const Mpi *a, const Mpi *p)
{
   error_t error;
   size_t m;
   size_t n;
   uint8_t *pos;
   PukccGcdParams params = {0};

   //Get the length of the input integer, in bytes
   m = mpiGetByteLength(a);
   //Get the length of the modulus, in bytes
   n = mpiGetByteLength(p);

   //Compute the length of the areas X, Y, A and Z
   n = MAX(n, m);
   n = (n + 7U) & ~3U;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy input integer
   params.x = cpkccImportMpi(&pos, a, n);
   //Copy modulus
   params.y = cpkccImportMpi(&pos, p, n);
   //Initialize output integer A
   params.a = cpkccWorkspace(&pos, n);
   //Initialize output integer Z
   params.z = cpkccWorkspace(&pos, n + 4);
   //Initialize workspace >
   params.w = cpkccWorkspace(&pos, 32);

   //Set GCD service parameters
   CPKCL(Specific).Gf2n = 0;
   CPKCL_GCD(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);
   CPKCL_GCD(nu1YBase) = CPKCC_FAR_TO_NEAR(params.y);
   CPKCL_GCD(nu1ABase) = CPKCC_FAR_TO_NEAR(params.a);
   CPKCL_GCD(nu1ZBase) = CPKCC_FAR_TO_NEAR(params.z);
   CPKCL_GCD(nu1WorkSpace) = CPKCC_FAR_TO_NEAR(params.w);
   CPKCL_GCD(u2Length) = n;

   //Calculate the modular inverse
   vCPKCL_Process(GCD, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Copy output integer Z
      error = mpiImport(r, params.a, n, MPI_FORMAT_LITTLE_ENDIAN);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
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
   size_t n;
   size_t modLen;
   size_t expLen;
   uint8_t *pos;
   PukccExpModParams params = {0};

   //Get the length of the input integer, in bytes
   n = mpiGetByteLength(a);

   //Get the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);
   modLen = (modLen + 3U) & ~3U;

   //Get the length of the exponent, in bytes
   expLen = mpiGetByteLength(e);
   expLen = (expLen + 3U) & ~3U;

   //Check the length of the input integer
   if(n > (2 * modLen + 4))
      return ERROR_INVALID_LENGTH;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = cpkccImportMpi(&pos, p, modLen + 4);
   //Initialize reduction constant
   params.cns = cpkccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = cpkccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = cpkccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   CPKCL(u2Option) = CPKCL_REDMOD_SETUP;
   CPKCL(Specific).CarryIn = 0;
   CPKCL(Specific).Gf2n = 0;
   CPKCL_RedMod(u2ModLength) = modLen;
   CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
   CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
   CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vCPKCL_Process(RedMod, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy input number
      params.x = cpkccImportMpi(&pos, a, 2 * modLen + 8);

      //Set RedMod service parameters
      CPKCL(u2Option) = CPKCL_REDMOD_REDUCTION | CPKCL_REDMOD_USING_FASTRED;
      CPKCL(Specific).CarryIn = 0;
      CPKCL(Specific).Gf2n = 0;
      CPKCL_RedMod(u2ModLength) = modLen;
      CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.x);
      CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

      //Perform fast modular reduction
      vCPKCL_Process(RedMod, pvCPKCLParam);
   }

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Set RedMod service parameters
      CPKCL(u2Option) = CPKCL_REDMOD_NORMALIZE;
      CPKCL(Specific).CarryIn = 0;
      CPKCL(Specific).Gf2n = 0;
      CPKCL_RedMod(u2ModLength) = modLen;
      CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.x);
      CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

      //Normalize the result
      vCPKCL_Process(RedMod, pvCPKCLParam);
   }

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //The number to be exponentiated is followed by four 32-bit words
      //that are used during the computations as a workspace
      pos = params.x + modLen;
      cpkccWorkspace(&pos, 16);

      //The exponent must be given with a supplemental word on the LSB
      //side (low addresses). This word shall be set to zero
      params.exp = cpkccWorkspace(&pos, 4);
      cpkccImportMpi(&pos, e, expLen);

      //Initialize workspace
      params.w = cpkccWorkspace(&pos, 3 * (modLen + 4) + 8);

      //Set ExpMod service parameters
      CPKCL(u2Option) = CPKCL_EXPMOD_REGULARRSA | CPKCL_EXPMOD_WINDOWSIZE_1 |
         CPKCL_EXPMOD_EXPINPKCCRAM;
      CPKCL_ExpMod(u2ModLength) = modLen;
      CPKCL_ExpMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_ExpMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_ExpMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);
      CPKCL_ExpMod(nu1PrecompBase) = CPKCC_FAR_TO_NEAR(params.w);
      CPKCL_ExpMod(u2ExpLength) = expLen;
      CPKCL_ExpMod(pfu1ExpBase) = params.exp;
      CPKCL_ExpMod(u1Blinding) = 0;

      //Perform modular exponentiation
      vCPKCL_Process(ExpMod, pvCPKCLParam);
   }

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Copy resulting integer
      error = mpiImport(r, params.x, modLen, MPI_FORMAT_LITTLE_ENDIAN);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief Test whether a number is probable prime
 * @param[in] a Pointer to a multiple precision integer
 * @return Error code
 **/

error_t mpiCheckProbablePrime(const Mpi *a)
{
   error_t error;
   uint_t k;
   size_t n;
   uint8_t *pos;
   PukccPrimeGenParams params = {0};

   //Get the length of the input integer, in bits
   n = mpiGetBitLength(a);

   //Prime numbers of a size lower than 96 bits cannot be tested by this
   //service
   if(n < 96)
      return ERROR_INVALID_LENGTH;

   //The number of repetitions controls the error probability
   if(n >= 1300)
   {
      k = 2;
   }
   else if(n >= 850)
   {
      k = 3;
   }
   else if(n >= 650)
   {
      k = 4;
   }
   else if(n >= 550)
   {
      k = 5;
   }
   else if(n >= 450)
   {
      k = 6;
   }
   else if(n >= 400)
   {
      k = 7;
   }
   else if(n >= 350)
   {
      k = 8;
   }
   else if(n >= 300)
   {
      k = 9;
   }
   else if(n >= 250)
   {
      k = 12;
   }
   else if(n >= 200)
   {
      k = 15;
   }
   else if(n >= 150)
   {
      k = 18;
   }
   else
   {
      k = 27;
   }

   //Get the length of the input integer, in bytes
   n = mpiGetByteLength(a);
   n = (n + 3U) & ~3U;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //One additional word is used on the LSB side of the NBase parameter. As
   //a consequence, the parameter nu1NBase must never be at the beginning of
   //the crypto RAM, but at least at one word from the beginning
   cpkccWorkspace(&pos, 4);

   //Copy the number to test
   params.n = cpkccImportMpi(&pos, a, n + 4);
   //Cns is used as a workspace
   params.cns = cpkccWorkspace(&pos, n + 12);
   //Rnd is used as a workspace
   params.rnd = cpkccWorkspace(&pos, MAX(n + 16, 64));
   //Precomp is used as a precomputation workspace
   params.w = cpkccWorkspace(&pos, MAX(3 * (n + 4), n + 72) + 8);
   //Exp is used as a workspace
   params.exp = cpkccWorkspace(&pos, n + 4);

   //Unused parameter
   params.r = 0;

   //Set PrimeGen service parameters
   CPKCL(u2Option) = CPKCL_PRIMEGEN_TEST | CPKCL_EXPMOD_FASTRSA |
      CPKCL_EXPMOD_WINDOWSIZE_1;
   CPKCL_PrimeGen(u2NLength) = n;
   CPKCL_PrimeGen(nu1NBase) = CPKCC_FAR_TO_NEAR(params.n);
   CPKCL_PrimeGen(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_PrimeGen(nu1RndBase) = CPKCC_FAR_TO_NEAR(params.rnd);
   CPKCL_PrimeGen(nu1PrecompBase) = CPKCC_FAR_TO_NEAR(params.w);
   CPKCL_PrimeGen(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
   CPKCL_PrimeGen(nu1ExpBase) = CPKCC_FAR_TO_NEAR(params.exp);
   CPKCL_PrimeGen(u1MillerRabinIterations) = k;
   CPKCL_PrimeGen(u2MaxIncrement) = 1;

   //Perform probable prime testing
   vCPKCL_Process(PrimeGen, pvCPKCLParam);

   //Check status code
   switch(CPKCL(u2Status))
   {
   case CPKCL_NUMBER_IS_PRIME:
      //The number is probably prime
      error = NO_ERROR;
      break;
   case CPKCL_NUMBER_IS_NOT_PRIME:
      //The number is not prime
      error = ERROR_INVALID_VALUE;
      break;
   default:
      //Report an error
      error = ERROR_FAILURE;
      break;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
   return error;
}

#endif
#if (RSA_SUPPORT == ENABLED)

/**
 * @brief RSA decryption primitive
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

   //Use the Chinese remainder algorithm?
   if(nLen > 0 && pLen > 0 && qLen > 0 && dpLen > 0 && dqLen > 0 && qinvLen > 0)
   {
      size_t cLen;
      size_t modLen;
      size_t expLen;
      uint8_t *pos;
      PukccCrtParams params = {0};

      //Get the length of the ciphertext, in bytes
      cLen = mpiGetByteLength(c);

      //Get the length of the modulus, in bytes
      modLen = MAX(pLen, qLen);
      modLen = MAX(modLen, 12);
      modLen = (modLen + 3U) & ~3U;

      //Get the length of the reduced exponents, in bytes
      expLen = MAX(dpLen, dqLen);
      expLen = (expLen + 3U) & ~3U;

      //Check the length of the ciphertext
      if(cLen > (2 * modLen))
         return ERROR_INVALID_LENGTH;

      //Acquire exclusive access to the CPKCC accelerator
      osAcquireMutex(&pic32cxmtCryptoMutex);

      //Point to the crypto memory
      pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

      //Copy primes
      params.q = cpkccImportMpi(&pos, &key->q, modLen + 4);
      params.p = cpkccImportMpi(&pos, &key->p, modLen + 4);

      //Copy input number
      params.x = cpkccImportMpi(&pos, c, 2 * modLen + 16);

      //The reduced exponents must be given with a supplemental word on the
      //LSB side (low addresses). This word shall be set to zero
      params.dq = cpkccWorkspace(&pos, 4);
      cpkccImportMpi(&pos, &key->dq, expLen);
      params.dp = cpkccWorkspace(&pos, 4);
      cpkccImportMpi(&pos, &key->dp, expLen);

      //Copy R value
      params.r = cpkccImportMpi(&pos, &key->qinv, modLen + 4);
      //Initialize workspace
      cpkccWorkspace(&pos, 3 * (modLen + 4) + MAX(64, 1 * (modLen + 4)) + 8);

      //Set CRT service parameters
      CPKCL(u2Option) = CPKCL_EXPMOD_REGULARRSA | CPKCL_EXPMOD_WINDOWSIZE_1 |
         CPKCL_EXPMOD_EXPINPKCCRAM;
      CPKCL_CRT(u2ModLength) = modLen;
      CPKCL_CRT(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.q);
      CPKCL_CRT(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);
      CPKCL_CRT(nu1PrecompBase) = CPKCC_FAR_TO_NEAR(params.r);
      CPKCL_CRT(u2ExpLength) = expLen;
      CPKCL_CRT(pfu1ExpBase) = params.dq;
      CPKCL_CRT(u1Blinding) = 0;

      //Perform modular exponentiation (with CRT)
      vCPKCL_Process(CRT, pvCPKCLParam);

      //Check status code
      if(CPKCL(u2Status) == CPKCL_OK)
      {
         //Copy resulting integer
         error = mpiImport(m, params.x, 2 * modLen, MPI_FORMAT_LITTLE_ENDIAN);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the CPKCC accelerator
      osReleaseMutex(&pic32cxmtCryptoMutex);
   }
   else if(nLen > 0 && dLen > 0)
   {
      //Perform modular exponentiation (without CRT)
      error = mpiExpMod(m, c, &key->d, &key->n);
   }
   else
   {
      //Invalid parameters
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}

#endif
#if (EC_SUPPORT == ENABLED)

/**
 * @brief Check whether the affine point S is on the curve
 * @param[in] curve Elliptic curve parameters
 * @param[in] s Affine representation of the point
 * @return TRUE if the affine point S is on the curve, else FALSE
 **/

bool_t ecIsPointAffine(const EcCurve *curve, const EcPoint *s)
{
   bool_t valid;
   size_t modLen;
   uint8_t *pos;
   PukccZpEcPointIsOnCurveParams params = {0};

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   modLen = (modLen + 3U) & ~3U;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = cpkccImportScalar(&pos, curve->p, modLen + 4);
   //Initialize reduction constant
   params.cns = cpkccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = cpkccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = cpkccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   CPKCL(u2Option) = CPKCL_REDMOD_SETUP;
   CPKCL(Specific).CarryIn = 0;
   CPKCL(Specific).Gf2n = 0;
   CPKCL_RedMod(u2ModLength) = modLen;
   CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
   CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
   CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vCPKCL_Process(RedMod, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy point coordinates
      params.point.x = cpkccImportScalar(&pos, s->x, modLen + 4);
      params.point.y = cpkccImportScalar(&pos, s->y, modLen + 4);
      params.point.z = cpkccWorkspace(&pos, modLen + 4);
      params.point.z[0] = 1;

      //Copy curve parameter a
      params.a = cpkccImportScalar(&pos, curve->a, modLen + 4);
      //Copy curve parameter b
      params.b = cpkccImportScalar(&pos, curve->b, modLen + 4);
      //Initialize workspace
      params.w = cpkccWorkspace(&pos, 4 * modLen + 28);

      //Set ZpEcPointIsOnCurve service parameters
      CPKCL_ZpEcPointIsOnCurve(u2ModLength) = modLen;
      CPKCL_ZpEcPointIsOnCurve(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_ZpEcPointIsOnCurve(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_ZpEcPointIsOnCurve(nu1PointBase) = CPKCC_FAR_TO_NEAR(params.point.x);
      CPKCL_ZpEcPointIsOnCurve(nu1AParam) = CPKCC_FAR_TO_NEAR(params.a);
      CPKCL_ZpEcPointIsOnCurve(nu1BParam) = CPKCC_FAR_TO_NEAR(params.b);
      CPKCL_ZpEcPointIsOnCurve(nu1Workspace) = CPKCC_FAR_TO_NEAR(params.w);

      //Test whether the point is on the curve
      vCPKCL_Process(ZpEcPointIsOnCurve, pvCPKCLParam);
   }

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //The point S is on the elliptic curve
      valid = TRUE;
   }
   else
   {
      //The point S is not on the elliptic curve
      valid = FALSE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return TRUE if the affine point S is on the curve, else FALSE
   return valid;
}


/**
 * @brief Recover affine representation
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Affine representation of the point
 * @param[in] s Projective representation of the point
 * @return Error code
 **/

error_t ecAffinify(const EcCurve *curve, EcPoint3 *r, const EcPoint3 *s)
{
   error_t error;
   size_t modLen;
   uint8_t *pos;
   PukccZpEcConvProjToAffineParams params = {0};

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   modLen = (modLen + 3U) & ~3U;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = cpkccImportScalar(&pos, curve->p, modLen + 4);
   //Initialize reduction constant
   params.cns = cpkccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = cpkccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = cpkccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   CPKCL(u2Option) = CPKCL_REDMOD_SETUP;
   CPKCL(Specific).CarryIn = 0;
   CPKCL(Specific).Gf2n = 0;
   CPKCL_RedMod(u2ModLength) = modLen;
   CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
   CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
   CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vCPKCL_Process(RedMod, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy point coordinates
      params.point.x = cpkccImportScalar(&pos, s->x, modLen + 4);
      params.point.y = cpkccImportScalar(&pos, s->y, modLen + 4);
      params.point.z = cpkccImportScalar(&pos, s->z, modLen + 4);
      //Initialize workspace
      params.w = cpkccWorkspace(&pos, 4 * modLen + 48);

      //Set ZpEccConvAffineToProjective service parameters
      CPKCL_ZpEcConvProjToAffine(u2ModLength) = modLen;
      CPKCL_ZpEcConvProjToAffine(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_ZpEcConvProjToAffine(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_ZpEcConvProjToAffine(nu1PointABase) = CPKCC_FAR_TO_NEAR(params.point.x);
      CPKCL_ZpEcConvProjToAffine(nu1Workspace) = CPKCC_FAR_TO_NEAR(params.w);

      //Convert point coordinates from projective to affine representation
      vCPKCL_Process(ZpEcConvProjToAffine, pvCPKCLParam);
   }

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Copy the x-coordinate of the result
      error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE, params.point.x, modLen,
         EC_SCALAR_FORMAT_LITTLE_ENDIAN);

      //Check error code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE, params.point.y, modLen,
            EC_SCALAR_FORMAT_LITTLE_ENDIAN);
      }

      //Check error code
      if(!error)
      {
         //Copy the z-coordinate of the result
         error = ecScalarImport(r->z, EC_MAX_MODULUS_SIZE, params.point.z, modLen,
            EC_SCALAR_FORMAT_LITTLE_ENDIAN);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
   return error;
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
   size_t modLen;
   size_t orderLen;
   uint8_t *pos;
   PukccZpEccMulParams params = {0};

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   modLen = (modLen + 3U) & ~3U;

   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;
   orderLen = (orderLen + 3U) & ~3U;

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = cpkccImportScalar(&pos, curve->p, modLen + 4);
   //Initialize reduction constant
   params.cns = cpkccWorkspace(&pos, modLen + 12);
   //Initialize workspace R
   params.r = cpkccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = cpkccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   CPKCL(u2Option) = CPKCL_REDMOD_SETUP;
   CPKCL(Specific).CarryIn = 0;
   CPKCL(Specific).Gf2n = 0;
   CPKCL_RedMod(u2ModLength) = modLen;
   CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
   CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
   CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vCPKCL_Process(RedMod, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy scalar number
      params.k = cpkccImportScalar(&pos, d, orderLen + 4);

      //Copy point coordinates
      params.point.x = cpkccImportScalar(&pos, s->x, modLen + 4);
      params.point.y = cpkccImportScalar(&pos, s->y, modLen + 4);
      params.point.z = cpkccWorkspace(&pos, modLen + 4);
      params.point.z[0] = 1;

      //Copy curve parameter a
      params.a = cpkccImportScalar(&pos, curve->a, modLen + 4);
      //Initialize workspace
      params.w = cpkccWorkspace(&pos, 8 * modLen + 44);

      //Set ZpEccMulFast service parameters
      CPKCL_ZpEccMul(u2ModLength) = modLen;
      CPKCL_ZpEccMul(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_ZpEccMul(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_ZpEccMul(u2KLength) = orderLen;
      CPKCL_ZpEccMul(nu1KBase) = CPKCC_FAR_TO_NEAR(params.k);
      CPKCL_ZpEccMul(nu1PointBase) = CPKCC_FAR_TO_NEAR(params.point.x);
      CPKCL_ZpEccMul(nu1ABase) = CPKCC_FAR_TO_NEAR(params.a);
      CPKCL_ZpEccMul(nu1Workspace) = CPKCC_FAR_TO_NEAR(params.w);

      //Perform scalar multiplication over GF(p)
      vCPKCL_Process(ZpEccMulFast, pvCPKCLParam);
   }

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Copy the x-coordinate of the result
      error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE, params.point.x, modLen,
         EC_SCALAR_FORMAT_LITTLE_ENDIAN);

      //Check error code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE, params.point.y, modLen,
            EC_SCALAR_FORMAT_LITTLE_ENDIAN);
      }

      //Check error code
      if(!error)
      {
         //Copy the z-coordinate of the result
         error = ecScalarImport(r->z, EC_MAX_MODULUS_SIZE, params.point.z, modLen,
            EC_SCALAR_FORMAT_LITTLE_ENDIAN);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
   return error;
}

#endif
#if (ECDSA_SUPPORT == ENABLED)

/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcPrivateKey *privateKey, const uint8_t *digest, size_t digestLen,
   EcdsaSignature *signature)
{
   error_t error;
   size_t modLen;
   size_t orderLen;
   uint8_t *pos;
   uint32_t k[EC_MAX_ORDER_SIZE];
   const EcCurve *curve;
   PukccZpEcDsaGenerateParams params = {0};

   //Check parameters
   if(privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get elliptic curve parameters
   curve = privateKey->curve;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   modLen = (modLen + 3U) & ~3U;

   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;
   orderLen = (orderLen + 3U) & ~3U;

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, (curve->orderSize + 7) / 8);

   //Generate a random number k such as 0 < k < q - 1
   error = ecScalarRand(curve, k, prngAlgo, prngContext);

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Check error code
   if(!error)
   {
      //Point to the crypto memory
      pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

      //Copy modulus
      params.mod = cpkccImportScalar(&pos, curve->p, modLen + 4);
      //Initialize reduction constant
      params.cns = cpkccWorkspace(&pos, orderLen + 12);
      //Initialize workspace R
      params.r = cpkccWorkspace(&pos, 64);
      //Initialize workspace X
      params.x = cpkccWorkspace(&pos, 2 * modLen + 8);

      //Set RedMod service parameters
      CPKCL(u2Option) = CPKCL_REDMOD_SETUP;
      CPKCL(Specific).CarryIn = 0;
      CPKCL(Specific).Gf2n = 0;
      CPKCL_RedMod(u2ModLength) = modLen;
      CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
      CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

      //Perform modular reduction setup
      vCPKCL_Process(RedMod, pvCPKCLParam);

      //Check status code
      if(CPKCL(u2Status) != CPKCL_OK)
         error = ERROR_FAILURE;
   }

   //Check error code
   if(!error)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy base point coordinates
      params.basePoint.x = cpkccImportScalar(&pos, curve->g.x, modLen + 4);
      params.basePoint.y = cpkccImportScalar(&pos, curve->g.y, modLen + 4);
      params.basePoint.z = cpkccImportScalar(&pos, curve->g.z, modLen + 4);

      //Copy base point order
      params.order = cpkccImportScalar(&pos, curve->q, orderLen + 4);
      //Copy curve parameter a
      params.a = cpkccImportScalar(&pos, curve->a, modLen + 4);
      //Copy private key
      params.privateKey = cpkccImportScalar(&pos, privateKey->d, orderLen + 4);
      //Copy random scalar
      params.k = cpkccImportScalar(&pos, k, orderLen + 4);
      //Copy digest
      params.h = cpkccImportArray(&pos, digest, digestLen, orderLen + 4);
      //Initialize workspace
      params.w = cpkccWorkspace(&pos, 8 * modLen + 44);

      //Set ZpEcDsaGenerateFast service parameters
      CPKCL_ZpEcDsaGenerate(u2ModLength) = modLen;
      CPKCL_ZpEcDsaGenerate(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_ZpEcDsaGenerate(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_ZpEcDsaGenerate(nu1PointABase) = CPKCC_FAR_TO_NEAR(params.basePoint.x);
      CPKCL_ZpEcDsaGenerate(nu1OrderPointBase) = CPKCC_FAR_TO_NEAR(params.order);
      CPKCL_ZpEcDsaGenerate(nu1ABase) = CPKCC_FAR_TO_NEAR(params.a);
      CPKCL_ZpEcDsaGenerate(nu1PrivateKey) = CPKCC_FAR_TO_NEAR(params.privateKey);
      CPKCL_ZpEcDsaGenerate(u2ScalarLength) = orderLen;
      CPKCL_ZpEcDsaGenerate(nu1ScalarNumber) = CPKCC_FAR_TO_NEAR(params.k);
      CPKCL_ZpEcDsaGenerate(nu1HashBase) = CPKCC_FAR_TO_NEAR(params.h);
      CPKCL_ZpEcDsaGenerate(nu1Workspace) = CPKCC_FAR_TO_NEAR(params.w);

      //Perform ECDSA signature generation
      vCPKCL_Process(ZpEcDsaGenerateFast, pvCPKCLParam);

      //Check status code
      if(CPKCL(u2Status) != CPKCL_OK)
         error = ERROR_FAILURE;
   }

   //Check error code
   if(!error)
   {
      //Save elliptic curve parameters
      signature->curve = curve;

      //Copy the first part of the ECDSA signature
      error = ecScalarImport(signature->r, EC_MAX_ORDER_SIZE,
         params.basePoint.x, orderLen, EC_SCALAR_FORMAT_LITTLE_ENDIAN);
   }

   //Check error code
   if(!error)
   {
      //Copy the second part of the ECDSA signature
      error = ecScalarImport(signature->s, EC_MAX_ORDER_SIZE,
         params.basePoint.x + orderLen + 4, orderLen,
         EC_SCALAR_FORMAT_LITTLE_ENDIAN);
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return error code
   return error;
}


/**
 * @brief ECDSA signature verification
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaVerifySignature(const EcPublicKey *publicKey,
   const uint8_t *digest, size_t digestLen, const EcdsaSignature *signature)
{
   error_t error;
   size_t modLen;
   size_t orderLen;
   uint8_t *pos;
   const EcCurve *curve;
   PukccZpEcDsaVerifyParams params = {0};

   //Check parameters
   if(publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(publicKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Verify that the public key is on the curve
   if(!ecIsPointAffine(publicKey->curve, &publicKey->q))
   {
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < r < q
   if(ecScalarCompInt(signature->r, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->r, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(ecScalarCompInt(signature->s, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->s, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //Get elliptic curve parameters
   curve = publicKey->curve;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   modLen = (modLen + 3U) & ~3U;

   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;
   orderLen = (orderLen + 3U) & ~3U;

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, (curve->orderSize + 7) / 8);

   //Acquire exclusive access to the CPKCC accelerator
   osAcquireMutex(&pic32cxmtCryptoMutex);

   //Point to the crypto memory
   pos = (uint8_t *) CPKCC_CRYPTO_RAM_BASE;

   //Copy modulus
   params.mod = cpkccImportScalar(&pos, curve->p, modLen + 4);
   //Initialize reduction constant
   params.cns = cpkccWorkspace(&pos, orderLen + 12);
   //Initialize workspace R
   params.r = cpkccWorkspace(&pos, 64);
   //Initialize workspace X
   params.x = cpkccWorkspace(&pos, 2 * modLen + 8);

   //Set RedMod service parameters
   CPKCL(u2Option) = CPKCL_REDMOD_SETUP;
   CPKCL(Specific).CarryIn = 0;
   CPKCL(Specific).Gf2n = 0;
   CPKCL_RedMod(u2ModLength) = modLen;
   CPKCL_RedMod(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
   CPKCL_RedMod(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
   CPKCL_RedMod(nu1RBase) = CPKCC_FAR_TO_NEAR(params.r);
   CPKCL_RedMod(nu1XBase) = CPKCC_FAR_TO_NEAR(params.x);

   //Perform modular reduction setup
   vCPKCL_Process(RedMod, pvCPKCLParam);

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //Point to the crypto memory
      pos = params.r;

      //Copy base point coordinates
      params.basePoint.x = cpkccImportScalar(&pos, curve->g.x, modLen + 4);
      params.basePoint.y = cpkccImportScalar(&pos, curve->g.y, modLen + 4);
      params.basePoint.z = cpkccImportScalar(&pos, curve->g.z, modLen + 4);

      //Copy base point order
      params.order = cpkccImportScalar(&pos, curve->q, orderLen + 4);
      //Copy curve parameter a
      params.a = cpkccImportScalar(&pos, curve->a, modLen + 4);

      //Copy public key
      params.publicKey.x = cpkccImportScalar(&pos, publicKey->q.x, modLen + 4);
      params.publicKey.y = cpkccImportScalar(&pos, publicKey->q.y, modLen + 4);
      params.publicKey.z = cpkccWorkspace(&pos, modLen + 4);
      params.publicKey.z[0] = 1;

      //Copy digest
      params.h = cpkccImportArray(&pos, digest, digestLen, orderLen + 4);

      //Copy signature
      params.r = cpkccImportScalar(&pos, signature->r, orderLen + 4);
      params.s = cpkccImportScalar(&pos, signature->s, orderLen + 4);

      //Initialize workspace
      params.w = cpkccWorkspace(&pos, 8 * modLen + 44);

      //Set ZpEcDsaVerifyFast service parameters
      CPKCL(u2Option) = 0;
      CPKCL_ZpEcDsaVerify(u2ModLength) = modLen;
      CPKCL_ZpEcDsaVerify(nu1ModBase) = CPKCC_FAR_TO_NEAR(params.mod);
      CPKCL_ZpEcDsaVerify(nu1CnsBase) = CPKCC_FAR_TO_NEAR(params.cns);
      CPKCL_ZpEcDsaVerify(nu1PointABase) = CPKCC_FAR_TO_NEAR(params.basePoint.x);
      CPKCL_ZpEcDsaVerify(nu1OrderPointBase) = CPKCC_FAR_TO_NEAR(params.order);
      CPKCL_ZpEcDsaVerify(nu1ABase) = CPKCC_FAR_TO_NEAR(params.a);
      CPKCL_ZpEcDsaVerify(nu1PointPublicKeyGen) = CPKCC_FAR_TO_NEAR(params.publicKey.x);
      CPKCL_ZpEcDsaVerify(u2ScalarLength) = orderLen;
      CPKCL_ZpEcDsaVerify(nu1HashBase) = CPKCC_FAR_TO_NEAR(params.h);
      CPKCL_ZpEcDsaVerify(nu1PointSignature) = CPKCC_FAR_TO_NEAR(params.r);
      CPKCL_ZpEcDsaVerify(nu1Workspace) = CPKCC_FAR_TO_NEAR(params.w);

      //Perform ECDSA signature verification
      vCPKCL_Process(ZpEcDsaVerifyFast, pvCPKCLParam);
   }

   //Check status code
   if(CPKCL(u2Status) == CPKCL_OK)
   {
      //The ECDSA signature is valid
      error = NO_ERROR;
   }
   else if(CPKCL(u2Status) == CPKCL_WRONG_SIGNATURE)
   {
      //The ECDSA signature is not valid
      error = ERROR_INVALID_SIGNATURE;
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the CPKCC accelerator
   osReleaseMutex(&pic32cxmtCryptoMutex);

   //Return status code
   return error;
}

#endif
#endif
