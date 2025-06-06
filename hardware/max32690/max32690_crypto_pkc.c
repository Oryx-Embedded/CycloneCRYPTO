/**
 * @file max32690_crypto_pkc.c
 * @brief MAX32690 public-key hardware accelerator
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
#include "mxc_device.h"
#include "mxc_sys.h"
#include "ctb.h"
#include "core/crypto.h"
#include "hardware/max32690/max32690_crypto.h"
#include "hardware/max32690/max32690_crypto_pkc.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/curve25519.h"
#include "ecc/curve448.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (MAX32690_CRYPTO_PKC_SUPPORT == ENABLED)


/**
 * @brief Set operand value
 * @param[in] offset MAA memory offset
 * @param[in] value Value of the operand
 * @param[in] length Length of the operand, in bits
 **/

void maaSetValue(uint_t offset, uint32_t value, uint_t length)
{
   uint_t i;
   volatile uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Get the length of the operand, in 64-bit words
   length = (length + 63) / 64;

   //Set the value of the operand
   p[0] = value;

   //Clear MAA memory
   for(i = 1; i < (length * 2); i++)
   {
      p[i] = 0;
   }
}


/**
 * @brief Import scalar
 * @param[in] offset MAA memory offset
 * @param[in] src Pointer to the scalar
 * @param[in] length Length of the operand, in bits
 **/

void maaImportScalar(uint_t offset, const uint32_t *src, uint_t length)
{
   uint_t i;
   volatile uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Get the length of the operand, in 32-bit words
   length = (length + 31) / 32;

   //Copy the scalar to the MAA memory
   for(i = 0; i < length; i++)
   {
      p[i] = src[i];
   }

   //Pad the operand with zeroes
   if((i % 2) != 0)
   {
      p[i] = 0;
   }
}


/**
 * @brief Import multiple-precision integer
 * @param[in] offset MAA memory offset
 * @param[in] src Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 **/

void maaImportMpi(uint_t offset, const Mpi *src, uint_t length)
{
   uint_t i;
   volatile uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Get the length of the operand, in 64-bit words
   length = (length + 63) / 64;

   //Copy the multiple-precision integer to the MAA memory
   for(i = 0; i < src->size && i < (length * 2); i++)
   {
      p[i] = src->data[i];
   }

   //Pad the operand with zeroes
   while(i < (length * 2))
   {
      p[i++] = 0;
   }
}


/**
 * @brief Export scalar
 * @param[in] offset MAA memory offset
 * @param[out] dest Pointer to the scalar
 * @param[in] length Length of the operand, in bits
 **/

void maaExportScalar(uint_t offset, uint32_t *dest, uint_t length)
{
   uint_t i;
   volatile uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Get the length of the operand, in 32-bit words
   length = (length + 31) / 32;

   //Copy the multiple-precision integer from the PKA RAM
   for(i = 0; i < length; i++)
   {
      dest[i] = p[i];
   }
}


/**
 * @brief Export multiple-precision integer
 * @param[in] offset MAA memory offset
 * @param[out] dest Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @return Error code
 **/

error_t maaExportMpi(uint_t offset, Mpi *dest, uint_t length)
{
   error_t error;
   uint_t i;
   volatile uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Get the length of the operand, in 32-bit words
   length = (length + 31) / 32;

   //Ajust the size of the multiple precision integer
   error = mpiGrow(dest, length);

   //Check status code
   if(!error)
   {
      //Copy the multiple-precision integer from the PKA RAM
      for(i = 0; i < length; i++)
      {
         dest->data[i] = p[i];
      }

      //Pad the resulting value with zeroes
      for(; i < dest->size; i++)
      {
         dest->data[i] = 0;
      }

      //Set the sign
      dest->sign = 1;
   }

   //Return status code
   return error;
}


#if (MPI_SUPPORT == ENABLED)

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
   uint_t modLen;

   //Get the length of the modulus, in bits
   modLen = mpiGetBitLength(p);

   //The accelerator supports operand lengths up to 2048 bits
   if(modLen <= 2048)
   {
      //Acquire exclusive access to the CTB module
      osAcquireMutex(&max32690CryptoMutex);

      //Reset the engine by setting CTB_CTRL.rst
      MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

      //Software must poll the CTB_CTRL.rst bit until it is set to 1 by
      //hardware, indicating the cryptographic accelerator is ready for use
      while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
      {
      }

      //Legacy support for the access behavior of the done flags
      MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

      //Specify the size of the modular operation
      MXC_CTB->maa_maws = modLen;

      //Copy the operand
      maaImportMpi(CTB_MAA_MEM_INSTANCE_0, a, modLen);
      //For exponentiation operations, b memory must contain the value of 1
      maaSetValue(CTB_MAA_MEM_INSTANCE_1, 1, modLen);
      //The exponent is always stored in memory instance 4
      maaImportMpi(CTB_MAA_MEM_INSTANCE_4, e, modLen);
      //The modulus is always stored in memory instance 5
      maaImportMpi(CTB_MAA_MEM_INSTANCE_5, p, modLen);

      //Set up a modular exponentiation operation (speed-optimized calculation)
      MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
         CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) | CTB_MAA_CTRL_OPT_Msk |
         CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_EXP_Val);

      //Start MAA operation
      MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

      //Wait for the MAA operation to complete
      while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
      {
      }

      //Copy the result
      error = maaExportMpi(CTB_MAA_MEM_INSTANCE_2, r, modLen);

      //Release exclusive access to the CTB module
      osReleaseMutex(&max32690CryptoMutex);
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
   uint_t modLen;

   //Get the length of the modulus, in bits
   modLen = mpiGetBitLength(p);

   //The accelerator supports operand lengths up to 2048 bits
   if(modLen <= 2048)
   {
      //Acquire exclusive access to the CTB module
      osAcquireMutex(&max32690CryptoMutex);

      //Reset the engine by setting CTB_CTRL.rst
      MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

      //Software must poll the CTB_CTRL.rst bit until it is set to 1 by
      //hardware, indicating the cryptographic accelerator is ready for use
      while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
      {
      }

      //Legacy support for the access behavior of the done flags
      MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

      //Specify the size of the modular operation
      MXC_CTB->maa_maws = modLen;

      //Copy the operand
      maaImportMpi(CTB_MAA_MEM_INSTANCE_0, a, modLen);
      //For exponentiation operations, b memory must contain the value of 1
      maaSetValue(CTB_MAA_MEM_INSTANCE_1, 1, modLen);
      //The exponent is always stored in memory instance 4
      maaImportMpi(CTB_MAA_MEM_INSTANCE_4, e, modLen);
      //The modulus is always stored in memory instance 5
      maaImportMpi(CTB_MAA_MEM_INSTANCE_5, p, modLen);

      //Set up a modular exponentiation operation
      MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
         CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
         CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_EXP_Val);

      //Start MAA operation
      MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

      //Wait for the MAA operation to complete
      while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
      {
      }

      //Copy the result
      error = maaExportMpi(CTB_MAA_MEM_INSTANCE_2, r, modLen);

      //Release exclusive access to the CTB module
      osReleaseMutex(&max32690CryptoMutex);
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
#if (EC_SUPPORT == ENABLED)

/**
 * @brief Modular addition
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void ecFieldAddMod2(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b)
{
   uint_t modLen;

   //Get the length of the modulus, in bits
   modLen = curve->fieldSize;

   //Acquire exclusive access to the CTB module
   osAcquireMutex(&max32690CryptoMutex);

   //Reset the engine by setting CTB_CTRL.rst
   MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

   //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
   //indicating the cryptographic accelerator is ready for use
   while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
   {
   }

   //Legacy support for the access behavior of the done flags
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

   //Specify the size of the modular operation
   MXC_CTB->maa_maws = modLen;

   //Copy the first operand
   maaImportScalar(CTB_MAA_MEM_INSTANCE_0, a, modLen);
   //Copy the second operand
   maaImportScalar(CTB_MAA_MEM_INSTANCE_1, b, modLen);
   //The modulus is always stored in memory instance 5
   maaImportScalar(CTB_MAA_MEM_INSTANCE_5, curve->p, modLen);

   //Set up a modular addition operation
   MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
      CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
      CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_ADD_Val);

   //Start MAA operation
   MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

   //Wait for the MAA operation to complete
   while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
   {
   }

   //Copy the result
   maaExportScalar(CTB_MAA_MEM_INSTANCE_2, r, modLen);

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);
}


/**
 * @brief Modular subtraction
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void ecFieldSubMod2(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b)
{
   uint_t modLen;

   //Get the length of the modulus, in bits
   modLen = curve->fieldSize;

   //Acquire exclusive access to the CTB module
   osAcquireMutex(&max32690CryptoMutex);

   //Reset the engine by setting CTB_CTRL.rst
   MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

   //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
   //indicating the cryptographic accelerator is ready for use
   while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
   {
   }

   //Legacy support for the access behavior of the done flags
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

   //Specify the size of the modular operation
   MXC_CTB->maa_maws = modLen;

   //Copy the first operand
   maaImportScalar(CTB_MAA_MEM_INSTANCE_0, a, modLen);
   //Copy the second operand
   maaImportScalar(CTB_MAA_MEM_INSTANCE_1, b, modLen);
   //The modulus is always stored in memory instance 5
   maaImportScalar(CTB_MAA_MEM_INSTANCE_5, curve->p, modLen);

   //Set up a modular subtraction operation
   MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
      CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
      CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_SUB_Val);

   //Start MAA operation
   MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

   //Wait for the MAA operation to complete
   while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
   {
   }

   //Copy the result
   maaExportScalar(CTB_MAA_MEM_INSTANCE_2, r, modLen);

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);
}


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
   uint_t modLen;

   //Check elliptic curve parameters
   if(curve->fieldInv == NULL)
   {
      //Get the length of the modulus, in bits
      modLen = curve->fieldSize;

      //Acquire exclusive access to the CTB module
      osAcquireMutex(&max32690CryptoMutex);

      //Reset the engine by setting CTB_CTRL.rst
      MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

      //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
      //indicating the cryptographic accelerator is ready for use
      while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
      {
      }

      //Legacy support for the access behavior of the done flags
      MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

      //Specify the size of the modular operation
      MXC_CTB->maa_maws = modLen;

      //Copy the first operand
      maaImportScalar(CTB_MAA_MEM_INSTANCE_0, a, modLen);
      //Copy the second operand
      maaImportScalar(CTB_MAA_MEM_INSTANCE_1, b, modLen);
      //The modulus is always stored in memory instance 5
      maaImportScalar(CTB_MAA_MEM_INSTANCE_5, curve->p, modLen);

      //Set up a modular multiplication operation
      MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
         CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
         CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_MUL_Val);

      //Start MAA operation
      MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

      //Wait for the MAA operation to complete
      while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
      {
      }

      //Copy the result
      maaExportScalar(CTB_MAA_MEM_INSTANCE_2, r, modLen);

      //Release exclusive access to the CTB module
      osReleaseMutex(&max32690CryptoMutex);
   }
   else
   {
      uint32_t u[EC_MAX_MODULUS_SIZE * 2];

      //Get the length of the modulus, in words
      modLen = (curve->fieldSize + 31) / 32;

      //Compute R = (A * B) mod p
      ecScalarMul(u, u + modLen, a, b, modLen);
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
   uint_t modLen;

   //Check elliptic curve parameters
   if(curve->fieldInv == NULL)
   {
      //Get the length of the modulus, in bits
      modLen = curve->fieldSize;

      //Acquire exclusive access to the CTB module
      osAcquireMutex(&max32690CryptoMutex);

      //Reset the engine by setting CTB_CTRL.rst
      MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

      //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
      //indicating the cryptographic accelerator is ready for use
      while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
      {
      }

      //Legacy support for the access behavior of the done flags
      MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

      //Specify the size of the modular operation
      MXC_CTB->maa_maws = modLen;

      //Copy the operand
      maaImportScalar(CTB_MAA_MEM_INSTANCE_1, a, modLen);
      //The modulus is always stored in memory instance 5
      maaImportScalar(CTB_MAA_MEM_INSTANCE_5, curve->p, modLen);

      //Set up a modular square operation
      MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
         CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
         CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_SQR_Val);

      //Start MAA operation
      MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

      //Wait for the MAA operation to complete
      while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
      {
      }

      //Copy the result
      maaExportScalar(CTB_MAA_MEM_INSTANCE_2, r, modLen);

      //Release exclusive access to the CTB module
      osReleaseMutex(&max32690CryptoMutex);
   }
   else
   {
      uint32_t u[EC_MAX_MODULUS_SIZE * 2];

      //Get the length of the modulus, in words
      modLen = (curve->fieldSize + 31) / 32;

      //Compute R = (A ^ 2) mod p
      ecScalarSqr(u, a, modLen);
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
   uint_t orderLen;

   //Get the length of the order, in bits
   orderLen = curve->orderSize;

   //Acquire exclusive access to the CTB module
   osAcquireMutex(&max32690CryptoMutex);

   //Reset the engine by setting CTB_CTRL.rst
   MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

   //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
   //indicating the cryptographic accelerator is ready for use
   while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
   {
   }

   //Legacy support for the access behavior of the done flags
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

   //Specify the size of the modular operation
   MXC_CTB->maa_maws = orderLen;

   //Copy the first operand
   maaImportScalar(CTB_MAA_MEM_INSTANCE_0, a, orderLen);
   //Copy the second operand
   maaImportScalar(CTB_MAA_MEM_INSTANCE_1, b, orderLen);
   //The modulus is always stored in memory instance 5
   maaImportScalar(CTB_MAA_MEM_INSTANCE_5, curve->q, orderLen);

   //Set up a modular multiplication operation
   MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
      CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
      CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_MUL_Val);

   //Start MAA operation
   MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

   //Wait for the MAA operation to complete
   while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
   {
   }

   //Copy the result
   maaExportScalar(CTB_MAA_MEM_INSTANCE_2, r, orderLen);

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);
}


/**
 * @brief Modular squaring
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^2 mod q
 * @param[in] a An integer such as 0 <= A < q
 **/

void ecScalarSqrMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint_t orderLen;

   //Get the length of the order, in bits
   orderLen = curve->orderSize;

   //Acquire exclusive access to the CTB module
   osAcquireMutex(&max32690CryptoMutex);

   //Reset the engine by setting CTB_CTRL.rst
   MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

   //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
   //indicating the cryptographic accelerator is ready for use
   while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
   {
   }

   //Legacy support for the access behavior of the done flags
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

   //Specify the size of the modular operation
   MXC_CTB->maa_maws = orderLen;

   //Copy the operand
   maaImportScalar(CTB_MAA_MEM_INSTANCE_1, a, orderLen);
   //The modulus is always stored in memory instance 5
   maaImportScalar(CTB_MAA_MEM_INSTANCE_5, curve->q, orderLen);

   //Set up a modular square operation
   MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
      CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
      CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_SQR_Val);

   //Start MAA operation
   MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

   //Wait for the MAA operation to complete
   while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
   {
   }

   //Copy the result
   maaExportScalar(CTB_MAA_MEM_INSTANCE_2, r, orderLen);

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);
}

#endif
#if (X25519_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Mul2(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   volatile uint32_t *p;

   //Acquire exclusive access to the CTB module
   osAcquireMutex(&max32690CryptoMutex);

   //Reset the engine by setting CTB_CTRL.rst
   MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

   //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
   //indicating the cryptographic accelerator is ready for use
   while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
   {
   }

   //Legacy support for the access behavior of the done flags
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

   //Specify the size of the modular operation
   MXC_CTB->maa_maws = 255;

   //Copy the first operand
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_0);
   p[0] = a[0];
   p[1] = a[1];
   p[2] = a[2];
   p[3] = a[3];
   p[4] = a[4];
   p[5] = a[5];
   p[6] = a[6];
   p[7] = a[7];

   //Copy the second operand
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_1);
   p[0] = b[0];
   p[1] = b[1];
   p[2] = b[2];
   p[3] = b[3];
   p[4] = b[4];
   p[5] = b[5];
   p[6] = b[6];
   p[7] = b[7];

   //The modulus is always stored in memory instance 5
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_5);
   p[0] = 0xFFFFFFED;
   p[1] = 0xFFFFFFFF;
   p[2] = 0xFFFFFFFF;
   p[3] = 0xFFFFFFFF;
   p[4] = 0xFFFFFFFF;
   p[5] = 0xFFFFFFFF;
   p[6] = 0xFFFFFFFF;
   p[7] = 0x7FFFFFFF;

   //Set up a modular multiplication operation
   MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
      CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
      CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_MUL_Val);

   //Start MAA operation
   MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

   //Wait for the MAA operation to complete
   while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
   {
   }

   //Copy the result
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_2);
   r[0] = p[0];
   r[1] = p[1];
   r[2] = p[2];
   r[3] = p[3];
   r[4] = p[4];
   r[5] = p[5];
   r[6] = p[6];
   r[7] = p[7];

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);
}

#endif
#if (X448_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve448Mul2(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   volatile uint32_t *p;

   //Acquire exclusive access to the CTB module
   osAcquireMutex(&max32690CryptoMutex);

   //Reset the engine by setting CTB_CTRL.rst
   MXC_CTB->ctrl = MXC_F_CTB_CTRL_RST;

   //Software must poll the CTB_CTRL.rst bit until it is set to 1 by hardware,
   //indicating the cryptographic accelerator is ready for use
   while((MXC_CTB->ctrl & MXC_F_CTB_CTRL_RDY) == 0)
   {
   }

   //Legacy support for the access behavior of the done flags
   MXC_CTB->ctrl |= MXC_F_CTB_CTRL_FLAG_MODE;

   //Specify the size of the modular operation
   MXC_CTB->maa_maws = 448;

   //Copy the first operand
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_0);
   p[0] = (a[1] << 28) | a[0];
   p[1] = (a[2] << 24) | (a[1] >> 4);
   p[2] = (a[3] << 20) | (a[2] >> 8);
   p[3] = (a[4] << 16) | (a[3] >> 12);
   p[4] = (a[5] << 12) | (a[4] >> 16);
   p[5] = (a[6] << 8) | (a[5] >> 20);
   p[6] = (a[7] << 4) | (a[6] >> 24);
   p[7] = (a[9] << 28) | a[8];
   p[8] = (a[10] << 24) | (a[9] >> 4);
   p[9] = (a[11] << 20) | (a[10] >> 8);
   p[10] = (a[12] << 16) | (a[11] >> 12);
   p[11] = (a[13] << 12) | (a[12] >> 16);
   p[12] = (a[14] << 8) | (a[13] >> 20);
   p[13] = (a[15] << 4) | (a[14] >> 24);

   //Copy the second operand
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_1);
   p[0] = (b[1] << 28) | b[0];
   p[1] = (b[2] << 24) | (b[1] >> 4);
   p[2] = (b[3] << 20) | (b[2] >> 8);
   p[3] = (b[4] << 16) | (b[3] >> 12);
   p[4] = (b[5] << 12) | (b[4] >> 16);
   p[5] = (b[6] << 8) | (b[5] >> 20);
   p[6] = (b[7] << 4) | (b[6] >> 24);
   p[7] = (b[9] << 28) | b[8];
   p[8] = (b[10] << 24) | (b[9] >> 4);
   p[9] = (b[11] << 20) | (b[10] >> 8);
   p[10] = (b[12] << 16) | (b[11] >> 12);
   p[11] = (b[13] << 12) | (b[12] >> 16);
   p[12] = (b[14] << 8) | (b[13] >> 20);
   p[13] = (b[15] << 4) | (b[14] >> 24);

   //The modulus is always stored in memory instance 5
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_5);
   p[0] = 0xFFFFFFFF;
   p[1] = 0xFFFFFFFF;
   p[2] = 0xFFFFFFFF;
   p[3] = 0xFFFFFFFF;
   p[4] = 0xFFFFFFFF;
   p[5] = 0xFFFFFFFF;
   p[6] = 0xFFFFFFFF;
   p[7] = 0xFFFFFFFE;
   p[8] = 0xFFFFFFFF;
   p[9] = 0xFFFFFFFF;
   p[10] = 0xFFFFFFFF;
   p[11] = 0xFFFFFFFF;
   p[12] = 0xFFFFFFFF;
   p[13] = 0xFFFFFFFF;

   //Set up a modular multiplication operation
   MXC_CTB->maa_ctrl = CTB_MAA_CTRL_TMA(6) | CTB_MAA_CTRL_RMA(4) |
      CTB_MAA_CTRL_BMA(2) | CTB_MAA_CTRL_AMA(0) |
      CTB_MAA_CTRL_CALC(CTB_MAA_CTRL_CALC_MOD_MUL_Val);

   //Start MAA operation
   MXC_CTB->maa_ctrl |= CTB_MAA_CTRL_START_Msk;

   //Wait for the MAA operation to complete
   while((MXC_CTB->ctrl & TB_CTRL_MAA_DONE_Msk) == 0)
   {
   }

   //Copy the result
   p = (uint32_t *) (MXC_BASE_CTB + CTB_MAA_MEM_INSTANCE_2);
   r[0] = p[0] & 0x0FFFFFFF;
   r[1] = p[0] >> 28 | ((p[1] << 4) & 0x0FFFFFF0);
   r[2] = p[1] >> 24 | ((p[2] << 8) & 0x0FFFFF00);
   r[3] = p[2] >> 20 | ((p[3] << 12) & 0x0FFFF000);
   r[4] = p[3] >> 16 | ((p[4] << 16) & 0x0FFF0000);
   r[5] = p[4] >> 12 | ((p[5] << 20) & 0x0FF00000);
   r[6] = p[5] >> 8 | ((p[6] << 24) & 0x0F000000);
   r[7] = p[6] >> 4;
   r[8] = p[7] & 0x0FFFFFFF;
   r[9] = p[7] >> 28 | ((p[8] << 4) & 0x0FFFFFF0);
   r[10] = p[8] >> 24 | ((p[9] << 8) & 0x0FFFFF00);
   r[11] = p[9] >> 20 | ((p[10] << 12) & 0x0FFFF000);
   r[12] = p[10] >> 16 | ((p[11] << 16) & 0x0FFF0000);
   r[13] = p[11] >> 12 | ((p[12] << 20) & 0x0FF00000);
   r[14] = p[12] >> 8 | ((p[13] << 24) & 0x0F000000);
   r[15] = p[13] >> 4;

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);
}

#endif
#endif
