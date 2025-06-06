/**
 * @file efm32gg11_crypto_pkc.c
 * @brief EFM32 Giant Gecko 11 public-key hardware accelerator
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
#include "em_device.h"
#include "em_crypto.h"
#include "core/crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto.h"
#include "hardware/efm32gg11/efm32gg11_crypto_pkc.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (EFM32GG11_CRYPTO_PKC_SUPPORT == ENABLED)
#if (EC_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void ecFieldMulMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b)
{
   //Check elliptic curve
   if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&efm32gg11CryptoMutex);

      //Set wide arithmetic configuration
      CRYPTO0->WAC = 0;
      CRYPTO0->CTRL = 0;

      //Set CRYPTO module parameters
      CRYPTO_ModulusSet(CRYPTO0, cryptoModulusEccP256);
      CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperandModulusBits);
      CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

      //Copy the first operand
      CRYPTO_DDataWrite(&CRYPTO0->DDATA1, a);

      //Copy the second operand
      CRYPTO_DDataWrite(&CRYPTO0->DDATA2, b);

      //Compute R = (A * B) mod p
      CRYPTO_EXECUTE_2(CRYPTO0,
         CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
         CRYPTO_CMD_INSTR_MMUL);

      //Wait for the instruction sequence to complete
      CRYPTO_InstructionSequenceWait(CRYPTO0);

      //Copy the resulting value
      CRYPTO_DDataRead(&CRYPTO0->DDATA0, r);

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&efm32gg11CryptoMutex);
   }
   else
   {
      uint_t pLen;
      uint32_t u[EC_MAX_MODULUS_SIZE * 2];

      //Get the length of the modulus, in words
      pLen = (curve->fieldSize + 31) / 32;

      //Compute R = (A * B) mod p
      ecScalarMul(u, u + pLen, a, b, pLen);
      curve->fieldMod(curve, r, u);
   }
}


/**
 * @brief Modular squaring
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^2 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void ecFieldSqrMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   //Check elliptic curve
   if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&efm32gg11CryptoMutex);

      //Set wide arithmetic configuration
      CRYPTO0->WAC = 0;
      CRYPTO0->CTRL = 0;

      //Set CRYPTO module parameters
      CRYPTO_ModulusSet(CRYPTO0, cryptoModulusEccP256);
      CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperandModulusBits);
      CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

      //Copy the operand
      CRYPTO_DDataWrite(&CRYPTO0->DDATA1, a);

      //Compute R = (A ^ 2) mod p
      CRYPTO_EXECUTE_3(CRYPTO0,
         CRYPTO_CMD_INSTR_DDATA1TODDATA2,
         CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
         CRYPTO_CMD_INSTR_MMUL);

      //Wait for the instruction sequence to complete
      CRYPTO_InstructionSequenceWait(CRYPTO0);

      //Copy the resulting value
      CRYPTO_DDataRead(&CRYPTO0->DDATA0, r);

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&efm32gg11CryptoMutex);
   }
   else
   {
      uint_t pLen;
      uint32_t u[EC_MAX_MODULUS_SIZE * 2];

      //Get the length of the modulus, in words
      pLen = (curve->fieldSize + 31) / 32;

      //Compute R = (A ^ 2) mod p
      ecScalarSqr(u, a, pLen);
      curve->fieldMod(curve, r, u);
   }
}


/**
 * @brief Modular multiplication
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A * B) mod q
 * @param[in] a An integer such as 0 <= A < q
 * @param[in] b An integer such as 0 <= B < q
 **/

void ecScalarMulMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b)
{
   //Check elliptic curve
   if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&efm32gg11CryptoMutex);

      //Set wide arithmetic configuration
      CRYPTO0->WAC = 0;
      CRYPTO0->CTRL = 0;

      //Set CRYPTO module parameters
      CRYPTO_ModulusSet(CRYPTO0, cryptoModulusEccP256Order);
      CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperandModulusBits);
      CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

      //Copy the first operand
      CRYPTO_DDataWrite(&CRYPTO0->DDATA1, a);

      //Copy the second operand
      CRYPTO_DDataWrite(&CRYPTO0->DDATA2, b);

      //Compute R = (A * B) mod q
      CRYPTO_EXECUTE_2(CRYPTO0,
         CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
         CRYPTO_CMD_INSTR_MMUL);

      //Wait for the instruction sequence to complete
      CRYPTO_InstructionSequenceWait(CRYPTO0);

      //Copy the resulting value
      CRYPTO_DDataRead(&CRYPTO0->DDATA0, r);

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&efm32gg11CryptoMutex);
   }
   else
   {
      uint_t qLen;
      uint32_t u[EC_MAX_ORDER_SIZE * 2];

      //Get the length of the order, in words
      qLen = (curve->orderSize + 31) / 32;

      //Compute R = (A * B) mod q
      ecScalarMul(u, u + qLen, a, b, qLen);
      curve->scalarMod(curve, r, u);
   }
}


/**
 * @brief Modular squaring
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^2 mod q
 * @param[in] a An integer such as 0 <= A < q
 **/

void ecScalarSqrMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   //Check elliptic curve
   if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      //Acquire exclusive access to the CRYPTO module
      osAcquireMutex(&efm32gg11CryptoMutex);

      //Set wide arithmetic configuration
      CRYPTO0->WAC = 0;
      CRYPTO0->CTRL = 0;

      //Set CRYPTO module parameters
      CRYPTO_ModulusSet(CRYPTO0, cryptoModulusEccP256Order);
      CRYPTO_MulOperandWidthSet(CRYPTO0, cryptoMulOperandModulusBits);
      CRYPTO_ResultWidthSet(CRYPTO0, cryptoResult256Bits);

      //Copy the operand
      CRYPTO_DDataWrite(&CRYPTO0->DDATA1, a);

      //Compute R = (A ^ 2) mod q
      CRYPTO_EXECUTE_3(CRYPTO0,
         CRYPTO_CMD_INSTR_DDATA1TODDATA2,
         CRYPTO_CMD_INSTR_SELDDATA0DDATA2,
         CRYPTO_CMD_INSTR_MMUL);

      //Wait for the instruction sequence to complete
      CRYPTO_InstructionSequenceWait(CRYPTO0);

      //Copy the resulting value
      CRYPTO_DDataRead(&CRYPTO0->DDATA0, r);

      //Release exclusive access to the CRYPTO module
      osReleaseMutex(&efm32gg11CryptoMutex);
   }
   else
   {
      uint_t qLen;
      uint32_t u[EC_MAX_ORDER_SIZE * 2];

      //Get the length of the order, in words
      qLen = (curve->orderSize + 31) / 32;

      //Compute R = (A ^ 2) mod q
      ecScalarSqr(u, a, qLen);
      curve->scalarMod(curve, r, u);
   }
}

#endif
#endif
