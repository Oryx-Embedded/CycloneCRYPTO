/**
 * @file esp32_c3_crypto_pkc.c
 * @brief ESP32-C3 public-key hardware accelerator
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
#include "soc/system_reg.h"
#include "soc/hwcrypto_reg.h"
#include "esp_private/periph_ctrl.h"
#include "hardware/esp32_c3/esp32_c3_crypto.h"
#include "hardware/esp32_c3/esp32_c3_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (ESP32_C3_CRYPTO_PKC_SUPPORT == ENABLED)

//Pre-computed values of -1/p[0] mod 2^32
#define SECP224R1_PRIME_M       0xFFFFFFFF
#define SECP256K1_PRIME_M       0xD2253531
#define SECP256R1_PRIME_M       0x00000001
#define SECP384R1_PRIME_M       0x00000001
#define SECP521R1_PRIME_M       0x00000001
#define BRAINPOOLP256R1_PRIME_M 0xCEFD89B9
#define BRAINPOOLP384R1_PRIME_M 0xEA9EC825
#define BRAINPOOLP512R1_PRIME_M 0x7D89EFC5
#define FRP256V1_PRIME_M        0x164E1155
#define SM2_PRIME_M             0x00000001
#define CURVE25519_PRIME_M      0x286BCA1B
#define CURVE448_PRIME_M        0x00000001

//Pre-computed values of -1/q[0] mod 2^32
#define SECP224R1_ORDER_M       0x6A1FC2EB
#define SECP256K1_ORDER_M       0x5588B13F
#define SECP256R1_ORDER_M       0xEE00BC4F
#define SECP384R1_ORDER_M       0xE88FDC45
#define SECP521R1_ORDER_M       0x79A995C7
#define BRAINPOOLP256R1_ORDER_M 0xCBB40EE9
#define BRAINPOOLP384R1_ORDER_M 0x5CB5BB93
#define BRAINPOOLP512R1_ORDER_M 0x0F1B7027
#define FRP256V1_ORDER_M        0x4FFF51DF
#define SM2_ORDER_M             0x72350975

//Pre-computed value of R^2 mod p (secp224r1)
const uint32_t SECP224R1_PRIME_R2[7] =
{
   0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000
};

//Pre-computed value of R^2 mod q (secp224r1)
const uint32_t SECP224R1_ORDER_R2[7] =
{
   0x3AD01289, 0x6BDAAE6C, 0x97A54552, 0x6AD09D91, 0xB1E97961, 0x1822BC47, 0xD4BAA4CF
};

//Pre-computed value of R^2 mod p (secp256k1)
const uint32_t SECP256K1_PRIME_R2[8] =
{
   0x000E90A1, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
};

//Pre-computed value of R^2 mod q (secp256k1)
const uint32_t SECP256K1_ORDER_R2[8] =
{
   0x67D7D140, 0x896CF214, 0x0E7CF878, 0x741496C2, 0x5BCD07C6, 0xE697F5E4, 0x81C69BC5, 0x9D671CD5
};

//Pre-computed value of R^2 mod p (secp256r1)
const uint32_t SECP256R1_PRIME_R2[8] =
{
   0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000004
};

//Pre-computed value of R^2 mod q (secp256r1)
const uint32_t SECP256R1_ORDER_R2[8] =
{
   0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C, 0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94
};

//Pre-computed value of R^2 mod p (secp384r1)
const uint32_t SECP384R1_PRIME_R2[12] =
{
   0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, 0xFFFFFFFE, 0x00000000, 0x00000002,
   0x00000001, 0x00000000, 0x00000000, 0x00000000
};

//Pre-computed value of R^2 mod q (secp384r1)
const uint32_t SECP384R1_ORDER_R2[12] =
{
   0x19B409A9, 0x2D319B24, 0xDF1AA419, 0xFF3D81E5, 0xFCB82947, 0xBC3E483A, 0x4AAB1CC5, 0xD40D4917,
   0x28266895, 0x3FB05B7A, 0x2B39BF21, 0x0C84EE01
};

//Pre-computed value of R^2 mod p (secp521r1)
const uint32_t SECP521R1_PRIME_R2[17] =
{
   0x00000000, 0x00004000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000
};

//Pre-computed value of R^2 mod q (secp521r1)
const uint32_t SECP521R1_ORDER_R2[17] =
{
   0x61C64CA7, 0x1163115A, 0x4374A642, 0x18354A56, 0x0791D9DC, 0x5D4DD6D3, 0xD3402705, 0x4FB35B72,
   0xB7756E3A, 0xCFF3D142, 0xA8E567BC, 0x5BCC6D61, 0x492D0D45, 0x2D8E03D1, 0x8C44383D, 0x5B5A3AFE,
   0x0000019A
};

//Pre-computed value of R^2 mod p (brainpoolP256r1)
const uint32_t BRAINPOOLP256R1_PRIME_R2[8] =
{
   0xA6465B6C, 0x8CFEDF7B, 0x614D4F4D, 0x5CCE4C26, 0x6B1AC807, 0xA1ECDACD, 0xE5957FA8, 0x4717AA21
};

//Pre-computed value of R^2 mod q (brainpoolP256r1)
const uint32_t BRAINPOOLP256R1_ORDER_R2[8] =
{
   0x3312FCA6, 0xE1D8D8DE, 0x1134E4A0, 0xF35D176A, 0x6C815CB0, 0x9B7F25E7, 0xC3236762, 0x0B25F1B9
};

//Pre-computed value of R^2 mod p (brainpoolP384r1)
const uint32_t BRAINPOOLP384R1_PRIME_R2[12] =
{
   0x40B64BDE, 0x087CEFFF, 0x3D7FD965, 0x53528334, 0xC9940899, 0x8E28F99C, 0x9918D5AF, 0x62140191,
   0xA57E052C, 0xD5C6EF3B, 0x178DF842, 0x36BF6883
};

//Pre-computed value of R^2 mod q (brainpoolP384r1)
const uint32_t BRAINPOOLP384R1_ORDER_R2[12] =
{
   0xDE771C8E, 0xAC4ED3A2, 0x2F2B6B6E, 0x37264E20, 0x9802688A, 0x2A927E3B, 0x52D748FF, 0x574A74CB,
   0x65165FDB, 0x8F886DC9, 0x614E97C2, 0x0CE8941A
};

//Pre-computed value of R^2 mod p (brainpoolP512r1)
const uint32_t BRAINPOOLP512R1_PRIME_R2[16] =
{
   0x6158F205, 0x49AD144A, 0x27157905, 0x793FB130, 0x905AFFD3, 0x53B7F9BC, 0x83514A25, 0xE0C19A77,
   0xD5898057, 0x19486FD8, 0xD42BFF83, 0xA16DAA5F, 0x2056EECC, 0x202E1940, 0xA9FF6450, 0x3C4C9D05
};

//Pre-computed value of R^2 mod q (brainpoolP512r1)
const uint32_t BRAINPOOLP512R1_ORDER_R2[16] =
{
   0xCDA81671, 0xD2A3681E, 0x95283DDD, 0x0886B758, 0x33B7627F, 0x3EC64BD0, 0x2F0207E8, 0xA6F230C7,
   0x3B790DE3, 0xD7F9CC26, 0x2F16BBDF, 0x723C37A2, 0x194B2E56, 0x95DF1B4C, 0x718407B0, 0xA794586A
};

//Pre-computed value of R^2 mod p (FRP256v1)
const uint32_t FRP256V1_PRIME_R2[8] =
{
   0xC99F1513, 0xB0C24E77, 0x0C960F92, 0x846F8083, 0xCE137EEE, 0x62B7012F, 0x88EB98AC, 0xB02C8F9F
};

//Pre-computed value of R^2 mod q (FRP256v1)
const uint32_t FRP256V1_ORDER_R2[8] =
{
   0xF849D44D, 0x1416B735, 0xBCC2D0E1, 0xB551ADB5, 0xC380D52D, 0xCFB26475, 0x15C243BB, 0x0DF1A20D
};

//Pre-computed value of R^2 mod p (curveSM2)
const uint32_t SM2_PRIME_R2[8] =
{
   0x00000003, 0x00000002, 0xFFFFFFFF, 0x00000002, 0x00000001, 0x00000001, 0x00000002, 0x00000004
};

//Pre-computed value of R^2 mod q (curveSM2)
const uint32_t SM2_ORDER_R2[8] =
{
   0x7C114F20, 0x901192AF, 0xDE6FA2FA, 0x3464504A, 0x3AFFE0D4, 0x620FC84C, 0xA22B3D3B, 0x1EB5E412
};


/**
 * @brief RSA module initialization
 **/

void esp32c3RsaInit(void)
{
   //Enable RSA module
   periph_module_enable(PERIPH_RSA_MODULE);

   //Clear SYSTEM_RSA_MEM_PD bit
   REG_CLR_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);

   //Software should query RSA_CLEAN_REG after being released from reset, and
   //before writing to any RSA Accelerator memory blocks or registers for the
   //first time
   while(REG_READ(RSA_QUERY_CLEAN_REG) == 0)
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

   //The accelerator supports large-number multiplication up to 1536 bits
   if(aLen <= 48 && bLen <= 48)
   {
      //All numbers in calculation must be of the same length
      n = 1;
      n = MAX(n, aLen);
      n = MAX(n, bLen);

      //Acquire exclusive access to the RSA module
      esp_crypto_mpi_lock_acquire();

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
      //Set mode register
      REG_WRITE(RSA_LENGTH_REG, (2 * n) - 1);

      //Copy the first operand to RSA_X_MEM
      for(i = 0; i < n; i++)
      {
         if(i < a->size)
         {
            REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a->data[i]);
         }
         else
         {
            REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
         }
      }

      //The second operand will not be written to the base address of the
      //RSA_Z_MEM memory. This area must be filled with zeroes
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_Z_BLOCK_BASE + i * 4, 0);
      }

      //The second operand must be written to the base address of the RSA_Z_MEM
      //memory plus the address offset N
      for(i = 0; i < n; i++)
      {
         if(i < b->size)
         {
            REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, b->data[i]);
         }
         else
         {
            REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, 0);
         }
      }

      //Start large-number multiplication
      REG_WRITE(RSA_MULT_START_REG, 1);

      //Wait for the operation to complete
      while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
      {
      }

      //Set the sign of the result
      r->sign = (a->sign == b->sign) ? 1 : -1;

      //The length of the result is 2 x N bits
      error = mpiGrow(r, n * 2);

      //Check status code
      if(!error)
      {
         //Read the result from RSA_Z_MEM
         for(i = 0; i < r->size; i++)
         {
            if(i < (n * 2))
            {
               r->data[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
            }
            else
            {
               r->data[i] = 0;
            }
         }
      }

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

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

   //Get the length of the modulus, in bits
   modLen = mpiGetBitLength(p);
   //Get the length of the exponent, in bits
   expLen = mpiGetBitLength(e);

   //The accelerator supports operand lengths up to 3072 bits
   if(modLen > 0 && modLen <= 3072 && expLen > 0 && expLen <= 3072)
   {
      //All numbers in calculation must be of the same length
      n = MAX(modLen, expLen);
      n = (n + 31) / 32;

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
         REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
         //Set mode register
         REG_WRITE(RSA_LENGTH_REG, n - 1);

         //Copy the operand to RSA_X_MEM
         for(i = 0; i < n; i++)
         {
            if(i < t.size)
            {
               REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, t.data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the exponent to RSA_Y_MEM
         for(i = 0; i < n; i++)
         {
            if(i < e->size)
            {
               REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, e->data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the modulus to RSA_M_MEM
         for(i = 0; i < n; i++)
         {
            if(i < p->size)
            {
               REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, p->data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, 0);
            }
         }

         //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
         for(i = 0; i < n; i++)
         {
            if(i < r2.size)
            {
               REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, r2.data[i]);
            }
            else
            {
               REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, 0);
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
         REG_WRITE(RSA_M_DASH_REG, m);

         //Enable search option
         REG_WRITE(RSA_SEARCH_ENABLE_REG, 1);
         REG_WRITE(RSA_SEARCH_POS_REG, expLen - 1);

         //Start modular exponentiation
         REG_WRITE(RSA_MODEXP_START_REG, 1);

         //Wait for the operation to complete
         while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
         {
         }

         //Adjust the size of the result if necessary
         error = mpiGrow(r, n);

         //Check status code
         if(!error)
         {
            //Read the result from RSA_Z_MEM
            for(i = 0; i < r->size; i++)
            {
               if(i < n)
               {
                  r->data[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
               }
               else
               {
                  r->data[i] = 0;
               }
            }
         }

         //Clear the interrupt flag
         REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

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

   //Acquire exclusive access to the RSA module
   esp_crypto_mpi_lock_acquire();

   //Clear the interrupt flag
   REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
   //Set mode register
   REG_WRITE(RSA_LENGTH_REG, (2 * n) - 1);

   //Copy the first operand to RSA_X_MEM
   for(i = 0; i < n; i++)
   {
      REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
   }

   //The second operand will not be written to the base address of the
   //RSA_Z_MEM memory. This area must be filled with zeroes
   for(i = 0; i < n; i++)
   {
      REG_WRITE(RSA_MEM_Z_BLOCK_BASE + i * 4, 0);
   }

   //The second operand must be written to the base address of the RSA_Z_MEM
   //memory plus the address offset N
   for(i = 0; i < n; i++)
   {
      REG_WRITE(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4, b[i]);
   }

   //Start large-number multiplication
   REG_WRITE(RSA_MULT_START_REG, 1);

   //Wait for the operation to complete
   while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
   {
   }

   //Check whether the low part of the multiplication should be calculated
   if(rl != NULL)
   {
      //Read the result from RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         rl[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
      }
   }

   //Check whether the high part of the multiplication should be calculated
   if(rh != NULL)
   {
      //Read the result from RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         rh[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + (n + i) * 4);
      }
   }

   //Clear the interrupt flag
   REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

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
   uint_t i;
   uint_t n;
   uint32_t m;
   const uint32_t *r2;

   //Get the length of the modulus, in words
   n = (curve->fieldSize + 31) / 32;

   //Load modular reduction constants
   if(osStrcmp(curve->name, "secp224r1") == 0)
   {
      r2 = SECP224R1_PRIME_R2;
      m = SECP224R1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "secp256k1") == 0)
   {
      r2 = SECP256K1_PRIME_R2;
      m = SECP256K1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      r2 = SECP256R1_PRIME_R2;
      m = SECP256R1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "secp384r1") == 0)
   {
      r2 = SECP384R1_PRIME_R2;
      m = SECP384R1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "secp521r1") == 0)
   {
      r2 = SECP521R1_PRIME_R2;
      m = SECP521R1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "brainpoolP256r1") == 0)
   {
      r2 = BRAINPOOLP256R1_PRIME_R2;
      m = BRAINPOOLP256R1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "brainpoolP384r1") == 0)
   {
      r2 = BRAINPOOLP384R1_PRIME_R2;
      m = BRAINPOOLP384R1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "brainpoolP512r1") == 0)
   {
      r2 = BRAINPOOLP512R1_PRIME_R2;
      m = BRAINPOOLP512R1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "FRP256v1") == 0)
   {
      r2 = FRP256V1_PRIME_R2;
      m = FRP256V1_PRIME_M;
   }
   else if(osStrcmp(curve->name, "curveSM2") == 0)
   {
      r2 = SM2_PRIME_R2;
      m = SM2_PRIME_M;
   }
   else
   {
      r2 = NULL;
      m = 0;
   }

   //Valid parameters?
   if(r2 != NULL && m != 0)
   {
      //Acquire exclusive access to the RSA module
      esp_crypto_mpi_lock_acquire();

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
      //Set mode register
      REG_WRITE(RSA_LENGTH_REG, n - 1);

      //Copy the first operand to RSA_X_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
      }

      //Copy the second operand to RSA_Y_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, b[i]);
      }

      //Copy the modulus to RSA_M_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, curve->p[i]);
      }

      //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, r2[i]);
      }

      //Write the value of M' to RSA_M_PRIME_REG
      REG_WRITE(RSA_M_DASH_REG, m);
      //Start large-number modular multiplication
      REG_WRITE(RSA_MOD_MULT_START_REG, 1);

      //Wait for the operation to complete
      while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
      {
      }

      //Read the result from RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         r[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
      }

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

      //Release exclusive access to the RSA module
      esp_crypto_mpi_lock_release();
   }
   else
   {
      uint32_t u[EC_MAX_MODULUS_SIZE * 2];

      //Compute R = (A * B) mod p
      ecScalarMul(u, u + n, a, b, n);
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
   //Compute R = (A ^ 2) mod p
   ecFieldMulMod(curve, r, a, a);
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
   uint_t i;
   uint_t n;
   uint32_t m;
   const uint32_t *r2;

   //Get the length of the order, in words
   n = (curve->orderSize + 31) / 32;

   //Load modular reduction constants
   if(osStrcmp(curve->name, "secp224r1") == 0)
   {
      r2 = SECP224R1_ORDER_R2;
      m = SECP224R1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "secp256k1") == 0)
   {
      r2 = SECP256K1_ORDER_R2;
      m = SECP256K1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      r2 = SECP256R1_ORDER_R2;
      m = SECP256R1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "secp384r1") == 0)
   {
      r2 = SECP384R1_ORDER_R2;
      m = SECP384R1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "secp521r1") == 0)
   {
      r2 = SECP521R1_ORDER_R2;
      m = SECP521R1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "brainpoolP256r1") == 0)
   {
      r2 = BRAINPOOLP256R1_ORDER_R2;
      m = BRAINPOOLP256R1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "brainpoolP384r1") == 0)
   {
      r2 = BRAINPOOLP384R1_ORDER_R2;
      m = BRAINPOOLP384R1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "brainpoolP512r1") == 0)
   {
      r2 = BRAINPOOLP512R1_ORDER_R2;
      m = BRAINPOOLP512R1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "FRP256v1") == 0)
   {
      r2 = FRP256V1_ORDER_R2;
      m = FRP256V1_ORDER_M;
   }
   else if(osStrcmp(curve->name, "curveSM2") == 0)
   {
      r2 = SM2_ORDER_R2;
      m = SM2_ORDER_M;
   }
   else
   {
      r2 = NULL;
      m = 0;
   }

   //Valid parameters?
   if(r2 != NULL && m != 0)
   {
      //Acquire exclusive access to the RSA module
      esp_crypto_mpi_lock_acquire();

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
      //Set mode register
      REG_WRITE(RSA_LENGTH_REG, n - 1);

      //Copy the first operand to RSA_X_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
      }

      //Copy the second operand to RSA_Y_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, b[i]);
      }

      //Copy the modulus to RSA_M_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, curve->q[i]);
      }

      //Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, r2[i]);
      }

      //Write the value of M' to RSA_M_PRIME_REG
      REG_WRITE(RSA_M_DASH_REG, m);
      //Start large-number modular multiplication
      REG_WRITE(RSA_MOD_MULT_START_REG, 1);

      //Wait for the operation to complete
      while(REG_READ(RSA_QUERY_INTERRUPT_REG) == 0)
      {
      }

      //Read the result from RSA_Z_MEM
      for(i = 0; i < n; i++)
      {
         r[i] = REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
      }

      //Clear the interrupt flag
      REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

      //Release exclusive access to the RSA module
      esp_crypto_mpi_lock_release();
   }
   else
   {
      uint32_t u[EC_MAX_ORDER_SIZE * 2];

      //Compute R = (A * B) mod q
      ecScalarMul(u, u + n, a, b, n);
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
   //Compute R = (A ^ 2) mod q
   ecScalarMulMod(curve, r, a, a);
}

#endif
#endif
