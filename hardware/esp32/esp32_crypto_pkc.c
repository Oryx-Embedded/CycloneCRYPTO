/**
 * @file esp32_crypto_pkc.c
 * @brief ESP32 public-key hardware accelerator
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
#include "esp_crypto_lock.h"
#include "soc/hwcrypto_reg.h"
#include "soc/dport_access.h"
#include "esp_private/periph_ctrl.h"
#include "hardware/esp32/esp32_crypto.h"
#include "hardware/esp32/esp32_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_CRYPTO_PKC_SUPPORT == ENABLED)


/**
 * @brief RSA module initialization
 **/

void esp32RsaInit(void)
{
   //Enable RSA module
   periph_module_enable(PERIPH_RSA_MODULE);

   //Software should query RSA_CLEAN_REG after being released from reset, and
   //before writing to any RSA Accelerator memory blocks or registers for the
   //first time
   while(DPORT_REG_READ(RSA_CLEAN_REG) == 0)
   {
   }
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
   size_t i;
   size_t n;
   size_t aLen;
   size_t bLen;

   //Get the length of the first operand, in 32-bit words
   aLen = mpiGetLength(a);
   //Get the length of the second operand, in 32-bit words
   bLen = mpiGetLength(b);

   //The accelerator supports large-number multiplication up to 2048 bits
   if(aLen <= 64 && bLen <= 64)
   {
      //All numbers in calculation must be of the same length
      n = 1;
      n = MAX(n, aLen);
      n = MAX(n, bLen);
      n = (n + 7) & ~7U;

      //Acquire exclusive access to the RSA module
      esp_crypto_mpi_lock_acquire();

      //Clear the interrupt flag
      DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);
      //Set mode register
      DPORT_REG_WRITE(RSA_MULT_MODE_REG, (n / 8) - 1 + 8);

      //Copy the first operand to RSA_X_MEM
      for(i = 0; i < n; i++)
      {
         if(i < a->size)
         {
            DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a->data[i]);
         }
         else
         {
            DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
         }
      }

      //The second operand will not be written to the base address of the
      //RSA_Z_MEM memory. This area must be filled with zeroes
      for(i = 0; i < n; i++)
      {
         DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + i * 4, 0);
      }

      //The second operand must be written to the base address of the RSA_Z_MEM
      //memory plus the address offset N
      for(i = 0; i < n; i++)
      {
         if(i < b->size)
         {
            DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, b->data[i]);
         }
         else
         {
            DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, 0);
         }
      }

      //Start large-number multiplication
      DPORT_REG_WRITE(RSA_MULT_START_REG, 1);

      //Wait for the operation to complete
      while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
      {
      }

      //Set the sign of the result
      r->sign = (a->sign == b->sign) ? 1 : -1;

      //The length of the result is 2 x N bits
      error = mpiGrow(r, n * 2);

      //Check status code
      if(!error)
      {
         //Disable interrupts only on current CPU
         DPORT_INTERRUPT_DISABLE();

         //Read the result from RSA_Z_MEM
         for(i = 0; i < r->size; i++)
         {
            if(i < (n * 2))
            {
               r->data[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
            }
            else
            {
               r->data[i] = 0;
            }
         }

         //Restore the previous interrupt level
         DPORT_INTERRUPT_RESTORE();
      }

      //Clear the interrupt flag
      DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

      //Release exclusive access to the RSA module
      esp_crypto_mpi_lock_release();
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
   size_t i;
   size_t n;
   size_t modLen;
   size_t expLen;
   uint32_t m;
   Mpi t;
   Mpi r2;

   //Initialize multiple precision integers
   mpiInit(&t);
   mpiInit(&r2);

   //Get the length of the modulus, in 32-bit words
   modLen = mpiGetLength(p);
   //Get the length of the exponent, in 32-bit words
   expLen = mpiGetLength(e);

   //The accelerator supports operand lengths up to 4096 bits
   if(modLen > 0 && modLen <= 128 && expLen > 0 && expLen <= 128)
   {
      //All numbers in calculation must be of the same length
      n = MAX(modLen, expLen);
      n = (n + 15) & ~15U;

      //Reduce the operand first
      error = mpiMod(&t, a, p);

      //Let R = b^n and pre-compute the quantity R^2 mod M
      if(!error)
      {
         error = mpiSetValue(&r2, 1);
      }

      if(!error)
      {
         error = mpiShiftLeft(&r2, n * 2 * 32);
      }

      if(!error)
      {
         error = mpiMod(&r2, &r2, p);
      }

      //Check status code
      if(!error)
      {
         //Acquire exclusive access to the RSA module
         esp_crypto_mpi_lock_acquire();

         //Clear the interrupt flag
         DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);
         //Set mode register
         DPORT_REG_WRITE(RSA_MODEXP_MODE_REG, (n / 16) - 1);

         //Copy the operand to RSA_X_MEM
         for(i = 0; i < n; i++)
         {
            if(i < t.size)
            {
               DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, t.data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the exponent to RSA_Y_MEM
         for(i = 0; i < n; i++)
         {
            if(i < e->size)
            {
               DPORT_REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, e->data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the modulus to RSA_M_MEM
         for(i = 0; i < n; i++)
         {
            if(i < p->size)
            {
               DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, p->data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
         for(i = 0; i < n; i++)
         {
            if(i < r2.size)
            {
               DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, r2.data[i]);
            }
            else
            {
               DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, 0);
            }
         }

         //Use Newton's method to compute the inverse of M[0] mod 2^32
         for(m = p->data[0], i = 0; i < 4; i++)
         {
            m = m * (2U - m * p->data[0]);
         }

         //Precompute M' = -1/M[0] mod 2^32;
         m = ~m + 1U;

         //Write the value of M' to RSA_M_PRIME_REG
         DPORT_REG_WRITE(RSA_M_DASH_REG, m);

         //Start modular exponentiation
         DPORT_REG_WRITE(RSA_MODEXP_START_REG, 1);

         //Wait for the operation to complete
         while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
         {
         }

         //Adjust the size of the result if necessary
         error = mpiGrow(r, n);

         //Check status code
         if(!error)
         {
            //Disable interrupts only on current CPU
            DPORT_INTERRUPT_DISABLE();

            //Read the result from RSA_Z_MEM
            for(i = 0; i < r->size; i++)
            {
               if(i < n)
               {
                  r->data[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
               }
               else
               {
                  r->data[i] = 0;
               }
            }

            //Restore the previous interrupt level
            DPORT_INTERRUPT_RESTORE();
         }

         //Clear the interrupt flag
         DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

         //Release exclusive access to the RSA module
         esp_crypto_mpi_lock_release();
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release previously allocated memory
   mpiFree(&t);
   mpiFree(&r2);

   //Return status code
   return error;
}

#endif
#if (EC_SUPPORT == ENABLED)

/**
 * @brief Multiplication of two integers
 * @param[out] rl Low part of the result R = (A * B) mod (2^32)^n
 * @param[out] rh High part of the result R = (A * B) / (2^32)^n
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] b An integer such as 0 <= B < (2^32)^n
 * @param[in] n Size of the operands, in words
 **/

void ecScalarMul(uint32_t *rl, uint32_t *rh, const uint32_t *a,
   const uint32_t *b, uint_t n)
{
   uint_t i;
   uint_t m;

   //The accelerator supports large-number multiplication with only four
   //operand lengths
   m = (n + 7) & ~7U;

   //Acquire exclusive access to the RSA module
   esp_crypto_mpi_lock_acquire();

   //Clear the interrupt flag
   DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);
   //Set mode register
   DPORT_REG_WRITE(RSA_MULT_MODE_REG, (m / 8) - 1 + 8);

   //Copy the first operand to RSA_X_MEM
   for(i = 0; i < m; i++)
   {
      if(i < n)
      {
         DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
      }
      else
      {
         DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
      }
   }

   //The second operand will not be written to the base address of the
   //RSA_Z_MEM memory. This area must be filled with zeroes
   for(i = 0; i < m; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + i * 4, 0);
   }

   //The second operand must be written to the base address of the RSA_Z_MEM
   //memory plus the address offset N
   for(i = 0; i < m; i++)
   {
      if(i < n)
      {
         DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (m + i) * 4, b[i]);
      }
      else
      {
         DPORT_REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (m + i) * 4, 0);
      }
   }

   //Start large-number multiplication
   DPORT_REG_WRITE(RSA_MULT_START_REG, 1);

   //Wait for the operation to complete
   while(DPORT_REG_READ(RSA_INTERRUPT_REG) == 0)
   {
   }

   //Disable interrupts only on current CPU
   DPORT_INTERRUPT_DISABLE();

   //Check whether the low part of the multiplication should be calculated
   if(rl != NULL)
   {
      //Read the result from RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         rl[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
      }
   }

   //Check whether the high part of the multiplication should be calculated
   if(rh != NULL)
   {
      //Read the result from RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         rh[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4);
      }
   }

   //Restore the previous interrupt level
   DPORT_INTERRUPT_RESTORE();
   //Clear the interrupt flag
   DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

   //Release exclusive access to the RSA module
   esp_crypto_mpi_lock_release();
}


/**
 * @brief Squaring operation
 * @param[out] r Result R = A ^ 2
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] n Size of the integer A, in words
 **/

void ecScalarSqr(uint32_t *r, const uint32_t *a, uint_t n)
{
   //Compute R = A ^ 2
   ecScalarMul(r, r + n, a, a, n);
}

#endif
#endif
