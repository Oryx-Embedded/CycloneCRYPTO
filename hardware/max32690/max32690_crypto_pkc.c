/**
 * @file max32690_crypto_pkc.c
 * @brief MAX32690 public-key hardware accelerator
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
 * @version 2.4.4
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
   uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Retrieve the length of the operand, in 64-bit words
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
 * @brief Import multiple-precision integer
 * @param[in] offset MAA memory offset
 * @param[in] a Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 **/

void maaImportMpi(uint_t offset, const Mpi *a, uint_t length)
{
   uint_t i;
   uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Retrieve the length of the operand, in 64-bit words
   length = (length + 63) / 64;

   //Copy the multiple-precision integer to the MAA memory
   for(i = 0; i < a->size && i < (length * 2); i++)
   {
      p[i] = a->data[i];
   }

   //Pad the operand with zeroes
   while(i < (length * 2))
   {
      p[i++] = 0;
   }
}


/**
 * @brief Export multiple-precision integer
 * @param[in] offset MAA memory offset
 * @param[out] r Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @return Error code
 **/

error_t maaExportMpi(uint_t offset, Mpi *r, uint_t length)
{
   error_t error;
   uint_t i;
   uint32_t *p;

   //Point to the specified MAA memory segment
   p = (uint32_t *) (MXC_BASE_CTB + offset);

   //Retrieve the length of the operand, in 32-bit words
   length = (length + 31) / 32;

   //Ajust the size of the multiple precision integer
   error = mpiGrow(r, length);

   //Check status code
   if(!error)
   {
      //Copy the multiple-precision integer from the PKA RAM
      for(i = 0; i < length; i++)
      {
         r->data[i] = p[i];
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

   //Retrieve the length of the modulus, in bits
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

   //Retrieve the length of the modulus, in bits
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
 * @brief Modular multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 * @return Error code
 **/

error_t ecMulMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b)
{
   error_t error;
   uint_t modLen;

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(&params->p);

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
   maaImportMpi(CTB_MAA_MEM_INSTANCE_0, a, modLen);
   //Copy the second operand
   maaImportMpi(CTB_MAA_MEM_INSTANCE_1, b, modLen);
   //The modulus is always stored in memory instance 5
   maaImportMpi(CTB_MAA_MEM_INSTANCE_5, &params->p, modLen);

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
   error = maaExportMpi(CTB_MAA_MEM_INSTANCE_2, r, modLen);

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief Fast modular squaring
 * @param[in] params EC domain parameters
 * @param[out] r Resulting integer R = (A ^ 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @return Error code
 **/

error_t ecSqrMod(const EcDomainParameters *params, Mpi *r, const Mpi *a)
{
   error_t error;
   uint_t modLen;

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(&params->p);

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
   maaImportMpi(CTB_MAA_MEM_INSTANCE_1, a, modLen);
   //The modulus is always stored in memory instance 5
   maaImportMpi(CTB_MAA_MEM_INSTANCE_5, &params->p, modLen);

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
   error = maaExportMpi(CTB_MAA_MEM_INSTANCE_2, r, modLen);

   //Release exclusive access to the CTB module
   osReleaseMutex(&max32690CryptoMutex);

   //Return status code
   return error;
}

#endif
#endif
