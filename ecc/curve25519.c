/**
 * @file curve25519.c
 * @brief Curve25519 elliptic curve (constant-time implementation)
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
#include "core/crypto.h"
#include "ecc/ec.h"
#include "ecc/curve25519.h"
#include "debug.h"

//Check crypto library configuration
#if (X25519_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED)

//Square root of -1 modulo p (constant)
static const int32_t CURVE25519_SQRT_MINUS_1[9] =
{
   0x0A0EA0B0, 0x0770D93A, 0x0BF91E31, 0x06300D5A, 0x1D7A72F4,
   0x004C9EFD, 0x1C2CAD34, 0x1009F83B, 0x002B8324
};


/**
 * @brief Set integer value
 * @param[out] a Pointer to the integer to be initialized
 * @param[in] b An integer such as 0 <= B < (2^29 - 1)
 **/

void curve25519SetInt(int32_t *a, int32_t b)
{
   uint_t i;

   //Set the value of the least significant word
   a[0] = b;

   //Initialize the rest of the integer
   for(i = 1; i < 9; i++)
   {
      a[i] = 0;
   }
}


/**
 * @brief Modular addition
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Add(int32_t *r, const int32_t *a, const int32_t *b)
{
#if (CURVE25519_SPEED_OPTIMIZATION_LEVEL <= 1)
   uint_t i;
   int32_t temp;

   //Compute R = A + B
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += a[i] + b[i];
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   temp += a[8] + b[8];
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (2^255 = 19)
   r[0] += temp * 19;
#else
   int32_t temp;

   //Compute R = A + B
   temp = a[0] + b[0];
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[1] + b[1];
   r[1] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[2] + b[2];
   r[2] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[3] + b[3];
   r[3] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[4] + b[4];
   r[4] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[5] + b[5];
   r[5] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[6] + b[6];
   r[6] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[7] + b[7];
   r[7] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[8] + b[8];
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (2^255 = 19)
   r[0] += temp * 19;
#endif
}


/**
 * @brief Modular addition
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve25519AddInt(int32_t *r, const int32_t *a, int32_t b)
{
   uint_t i;
   int32_t temp;

   //Compute R = A + B
   for(temp = b, i = 0; i < 8; i++)
   {
      temp += a[i];
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   temp += a[8];
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (2^255 = 19)
   r[0] += temp * 19;
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Sub(int32_t *r, const int32_t *a, const int32_t *b)
{
#if (CURVE25519_SPEED_OPTIMIZATION_LEVEL <= 1)
   uint_t i;
   int32_t temp;

   //Compute R = A - B
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += a[i] - b[i];
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   temp += a[8] - b[8];
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (2^255 = 19)
   r[0] += temp * 19;
#else
   int32_t temp;

   //Compute R = A - B
   temp = a[0] - b[0];
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[1] - b[1];
   r[1] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[2] - b[2];
   r[2] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[3] - b[3];
   r[3] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[4] - b[4];
   r[4] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[5] - b[5];
   r[5] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[6] - b[6];
   r[6] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[7] - b[7];
   r[7] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += a[8] - b[8];
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction
   r[0] += temp * 19;
#endif
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 **/

void curve25519SubInt(int32_t *r, const int32_t *a, int32_t b)
{
   uint_t i;
   int32_t temp;

   //Compute R = A - B
   for(temp = -b, i = 0; i < 8; i++)
   {
      temp += a[i];
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   temp += a[8];
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (2^255 = 19)
   r[0] += temp * 19;
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

__weak_func void curve25519Mul(int32_t *r, const int32_t *a, const int32_t *b)
{
#if (CURVE25519_SPEED_OPTIMIZATION_LEVEL == 0)
   uint_t i;
   uint_t j;
   int64_t temp;
   int32_t u[18];

   //Comba's method is used to perform multiplication
   for(temp = 0, i = 0; i < 18; i++)
   {
      //The algorithm computes the products, column by column
      if(i < 9)
      {
         //Inner loop
         for(j = 0; j <= i; j++)
         {
            temp += (int64_t) a[j] * b[i - j];
         }
      }
      else
      {
         //Inner loop
         for(j = i - 8; j < 9; j++)
         {
            temp += (int64_t) a[j] * b[i - j];
         }
      }

      //At the bottom of each column, the final result is written to memory
      u[i] = temp & 0x1FFFFFFF;
      //Propagate the carry upwards
      temp >>= 29;
   }

   //Perform modular reduction (first pass)
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += u[i];
      temp += (int64_t) u[i + 9] * 1216;
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   temp += u[8];
   temp += (int64_t) u[17] * 1216;
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (second pass)
   temp *= 19;
   temp += r[0];
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   r[1] += temp & 0xFFFFFFFF;
#else
   int64_t temp;
   int32_t u[18];

   //Compute R = A * B
   temp = (int64_t) a[0] * b[0];
   u[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[1];
   temp += (int64_t) a[1] * b[0];
   u[1] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[2];
   temp += (int64_t) a[1] * b[1];
   temp += (int64_t) a[2] * b[0];
   u[2] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[3];
   temp += (int64_t) a[1] * b[2];
   temp += (int64_t) a[2] * b[1];
   temp += (int64_t) a[3] * b[0];
   u[3] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[4];
   temp += (int64_t) a[1] * b[3];
   temp += (int64_t) a[2] * b[2];
   temp += (int64_t) a[3] * b[1];
   temp += (int64_t) a[4] * b[0];
   u[4] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[5];
   temp += (int64_t) a[1] * b[4];
   temp += (int64_t) a[2] * b[3];
   temp += (int64_t) a[3] * b[2];
   temp += (int64_t) a[4] * b[1];
   temp += (int64_t) a[5] * b[0];
   u[5] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[6];
   temp += (int64_t) a[1] * b[5];
   temp += (int64_t) a[2] * b[4];
   temp += (int64_t) a[3] * b[3];
   temp += (int64_t) a[4] * b[2];
   temp += (int64_t) a[5] * b[1];
   temp += (int64_t) a[6] * b[0];
   u[6] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[7];
   temp += (int64_t) a[1] * b[6];
   temp += (int64_t) a[2] * b[5];
   temp += (int64_t) a[3] * b[4];
   temp += (int64_t) a[4] * b[3];
   temp += (int64_t) a[5] * b[2];
   temp += (int64_t) a[6] * b[1];
   temp += (int64_t) a[7] * b[0];
   u[7] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[0] * b[8];
   temp += (int64_t) a[1] * b[7];
   temp += (int64_t) a[2] * b[6];
   temp += (int64_t) a[3] * b[5];
   temp += (int64_t) a[4] * b[4];
   temp += (int64_t) a[5] * b[3];
   temp += (int64_t) a[6] * b[2];
   temp += (int64_t) a[7] * b[1];
   temp += (int64_t) a[8] * b[0];
   u[8] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[1] * b[8];
   temp += (int64_t) a[2] * b[7];
   temp += (int64_t) a[3] * b[6];
   temp += (int64_t) a[4] * b[5];
   temp += (int64_t) a[5] * b[4];
   temp += (int64_t) a[6] * b[3];
   temp += (int64_t) a[7] * b[2];
   temp += (int64_t) a[8] * b[1];
   u[9] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[2] * b[8];
   temp += (int64_t) a[3] * b[7];
   temp += (int64_t) a[4] * b[6];
   temp += (int64_t) a[5] * b[5];
   temp += (int64_t) a[6] * b[4];
   temp += (int64_t) a[7] * b[3];
   temp += (int64_t) a[8] * b[2];
   u[10] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[3] * b[8];
   temp += (int64_t) a[4] * b[7];
   temp += (int64_t) a[5] * b[6];
   temp += (int64_t) a[6] * b[5];
   temp += (int64_t) a[7] * b[4];
   temp += (int64_t) a[8] * b[3];
   u[11] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[4] * b[8];
   temp += (int64_t) a[5] * b[7];
   temp += (int64_t) a[6] * b[6];
   temp += (int64_t) a[7] * b[5];
   temp += (int64_t) a[8] * b[4];
   u[12] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[5] * b[8];
   temp += (int64_t) a[6] * b[7];
   temp += (int64_t) a[7] * b[6];
   temp += (int64_t) a[8] * b[5];
   u[13] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[6] * b[8];
   temp += (int64_t) a[7] * b[7];
   temp += (int64_t) a[8] * b[6];
   u[14] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[7] * b[8];
   temp += (int64_t) a[8] * b[7];
   u[15] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[8] * b[8];
   u[16] = temp & 0x1FFFFFFF;
   temp >>= 29;
   u[17] = temp & 0xFFFFFFFF;

   //Perform modular reduction (first pass)
   temp = u[0];
   temp += (int64_t) u[9] * 1216;
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[1];
   temp += (int64_t) u[10] * 1216;
   r[1] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[2];
   temp += (int64_t) u[11] * 1216;
   r[2] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[3];
   temp += (int64_t) u[12] * 1216;
   r[3] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[4];
   temp += (int64_t) u[13] * 1216;
   r[4] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[5];
   temp += (int64_t) u[14] * 1216;
   r[5] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[6];
   temp += (int64_t) u[15] * 1216;
   r[6] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[7];
   temp += (int64_t) u[16] * 1216;
   r[7] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += u[8];
   temp += (int64_t) u[17] * 1216;
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (second pass)
   temp *= 19;
   temp += r[0];
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   r[1] += temp & 0xFFFFFFFF;
#endif
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^29 - 1)
 **/

void curve25519MulInt(int32_t *r, const int32_t *a, int32_t b)
{
#if (CURVE25519_SPEED_OPTIMIZATION_LEVEL == 0)
   int_t i;
   int64_t temp;

   //Compute R = A * B
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += (int64_t) a[i] * b;
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   temp += (int64_t) a[8] * b;
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (2^255 = 19)
   temp *= 19;
   temp += r[0];
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   r[1] += temp & 0xFFFFFFFF;
#else
   int64_t temp;

   //Compute R = A * B
   temp = (int64_t) a[0] * b;
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[1] * b;
   r[1] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[2] * b;
   r[2] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[3] * b;
   r[3] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[4] * b;
   r[4] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[5] * b;
   r[5] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[6] * b;
   r[6] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[7] * b;
   r[7] = temp & 0x1FFFFFFF;
   temp >>= 29;
   temp += (int64_t) a[8] * b;
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (2^255 = 19)
   temp *= 19;
   temp += r[0];
   r[0] = temp & 0x1FFFFFFF;
   temp >>= 29;
   r[1] += temp & 0xFFFFFFFF;
#endif
}


/**
 * @brief Modular squaring
 * @param[out] r Resulting integer R = (A ^ 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

__weak_func void curve25519Sqr(int32_t *r, const int32_t *a)
{
   //Compute R = (A ^ 2) mod p
   curve25519Mul(r, a, a);
}


/**
 * @brief Raise an integer to power 2^n
 * @param[out] r Resulting integer R = (A ^ (2^n)) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] n An integer such as n >= 1
 **/

void curve25519Pwr2(int32_t *r, const int32_t *a, uint_t n)
{
   uint_t i;

   //Pre-compute (A ^ 2) mod p
   curve25519Sqr(r, a);

   //Compute R = (A ^ (2^n)) mod p
   for(i = 1; i < n; i++)
   {
      curve25519Sqr(r, r);
   }
}


/**
 * @brief Modular multiplicative inverse
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void curve25519Inv(int32_t *r, const int32_t *a)
{
   int32_t u[9];
   int32_t v[9];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   curve25519Sqr(u, a);
   curve25519Mul(u, u, a); //A^(2^2 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^3 - 1)
   curve25519Pwr2(u, v, 3);
   curve25519Mul(u, u, v); //A^(2^6 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^7 - 1)
   curve25519Pwr2(u, v, 7);
   curve25519Mul(u, u, v); //A^(2^14 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^15 - 1)
   curve25519Pwr2(u, v, 15);
   curve25519Mul(u, u, v); //A^(2^30 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^31 - 1)
   curve25519Pwr2(u, v, 31);
   curve25519Mul(v, u, v); //A^(2^62 - 1)
   curve25519Pwr2(u, v, 62);
   curve25519Mul(u, u, v); //A^(2^124 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); //A^(2^125 - 1)
   curve25519Pwr2(u, v, 125);
   curve25519Mul(u, u, v); //A^(2^250 - 1)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, a); //A^(2^252 - 3)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, a); //A^(2^254 - 11)
   curve25519Sqr(u, u);
   curve25519Mul(r, u, a); //A^(2^255 - 21)
}


/**
 * @brief Compute the square root of (A / B) modulo p
 * @param[out] r Resulting integer R = (A / B)^(1 / 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 < B < p
 * @return The function returns 0 if the square root exists, else 1
 **/

uint32_t curve25519Sqrt(int32_t *r, const int32_t *a, const int32_t *b)
{
   uint32_t res1;
   uint32_t res2;
   int32_t c[9];
   int32_t u[9];
   int32_t v[9];
   int32_t w[9];

   //Compute the candidate root (A / B)^((p + 3) / 8). This can be done
   //with the following trick, using a single modular powering for both the
   //inversion of B and the square root: A * B^3 * (A * B^7)^((p - 5) / 8)
   curve25519Sqr(v, b);
   curve25519Mul(v, v, b);
   curve25519Sqr(v, v);
   curve25519Mul(v, v, b);

   //Compute C = A * B^7
   curve25519Mul(c, a, v);

   //Compute U = C^((p - 5) / 8)
   curve25519Sqr(u, c);
   curve25519Mul(u, u, c); //C^(2^2 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^3 - 1)
   curve25519Pwr2(u, v, 3);
   curve25519Mul(u, u, v); //C^(2^6 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^7 - 1)
   curve25519Pwr2(u, v, 7);
   curve25519Mul(u, u, v); //C^(2^14 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^15 - 1)
   curve25519Pwr2(u, v, 15);
   curve25519Mul(u, u, v); //C^(2^30 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^31 - 1)
   curve25519Pwr2(u, v, 31);
   curve25519Mul(v, u, v); //C^(2^62 - 1)
   curve25519Pwr2(u, v, 62);
   curve25519Mul(u, u, v); //C^(2^124 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); //C^(2^125 - 1)
   curve25519Pwr2(u, v, 125);
   curve25519Mul(u, u, v); //C^(2^250 - 1)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, c); //C^(2^252 - 3)

   //The first candidate root is U = A * B^3 * (A * B^7)^((p - 5) / 8)
   curve25519Mul(u, u, a);
   curve25519Sqr(v, b);
   curve25519Mul(v, v, b);
   curve25519Mul(u, u, v);
   curve25519Canonicalize(u, u);

   //The second candidate root is V = U * sqrt(-1)
   curve25519Mul(v, u, CURVE25519_SQRT_MINUS_1);
   curve25519Canonicalize(v, v);

   //Reduce non-canonical values of A
   curve25519Canonicalize(w, a);

   //Calculate C = B * U^2
   curve25519Sqr(c, u);
   curve25519Mul(c, c, b);
   curve25519Canonicalize(c, c);

   //Check whether B * U^2 = A
   res1 = curve25519Comp(c, w);

   //Calculate C = B * V^2
   curve25519Sqr(c, v);
   curve25519Mul(c, c, b);
   curve25519Canonicalize(c, c);

   //Check whether B * V^2 = A
   res2 = curve25519Comp(c, w);

   //Select the first or the second candidate root
   curve25519Select(r, u, v, res1);

   //Return 0 if the square root exists
   return res1 & res2;
}


/**
 * @brief Reduce non-canonical value
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < (2^255 - 1)
 **/

void curve25519Canonicalize(int32_t *r, const int32_t *a)
{
   uint_t i;
   int32_t temp;
   int32_t b[9];

   //Perform modular reduction (first pass)
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += a[i];
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   temp += a[8];
   r[8] = temp & 0x007FFFFF;
   temp >>= 23;

   //Perform modular reduction (second pass)
   for(temp *= 19, i = 0; i < 9; i++)
   {
      temp += r[i];
      r[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   //Compute B = A + 19
   for(temp = 19, i = 0; i < 9; i++)
   {
      temp += r[i];
      b[i] = temp & 0x1FFFFFFF;
      temp >>= 29;
   }

   //Compute B = A - (2^255 - 19)
   b[8] -= 0x00800000;
   b[8] &= 0x00FFFFFF;

   //If B < (2^255 - 19) then R = B, else R = A
   curve25519Select(r, b, r, (b[8] & 0x00800000) >> 23);
}


/**
 * @brief Copy an integer
 * @param[out] a Pointer to the destination integer
 * @param[in] b Pointer to the source integer
 **/

void curve25519Copy(int32_t *a, const int32_t *b)
{
   uint_t i;

   //Copy the value of the integer
   for(i = 0; i < 9; i++)
   {
      a[i] = b[i];
   }
}


/**
 * @brief Conditional swap
 * @param[in,out] a Pointer to the first integer
 * @param[in,out] b Pointer to the second integer
 * @param[in] c Condition variable
 **/

void curve25519Swap(int32_t *a, int32_t *b, uint32_t c)
{
   uint_t i;
   uint32_t mask;
   uint32_t dummy;

   //The mask is the all-1 or all-0 word
   mask = ~c + 1;

   //Conditional swap
   for(i = 0; i < 9; i++)
   {
      //Constant time implementation
      dummy = mask & (a[i] ^ b[i]);
      a[i] ^= dummy;
      b[i] ^= dummy;
   }
}


/**
 * @brief Select an integer
 * @param[out] r Pointer to the destination integer
 * @param[in] a Pointer to the first source integer
 * @param[in] b Pointer to the second source integer
 * @param[in] c Condition variable
 **/

void curve25519Select(int32_t *r, const int32_t *a, const int32_t *b,
   uint32_t c)
{
   uint_t i;
   uint32_t mask;

   //The mask is the all-1 or all-0 word
   mask = c - 1;

   //Select between A and B
   for(i = 0; i < 9; i++)
   {
      //Constant time implementation
      r[i] = (a[i] & mask) | (b[i] & ~mask);
   }
}


/**
 * @brief Compare integers
 * @param[in] a Pointer to the first integer
 * @param[in] b Pointer to the second integer
 * @return The function returns 0 if the A = B, else 1
 **/

uint32_t curve25519Comp(const int32_t *a, const int32_t *b)
{
   uint_t i;
   uint32_t mask;

   //Initialize mask
   mask = 0;

   //Compare A and B
   for(i = 0; i < 9; i++)
   {
      //Constant time implementation
      mask |= a[i] ^ b[i];
   }

   //Return 0 if A = B, else 1
   return ((uint32_t) (mask | (~mask + 1))) >> 31;
}


/**
 * @brief Import an octet string
 * @param[out] a Pointer to resulting integer
 * @param[in] data Octet string to be converted
 **/

void curve25519Import(int32_t *a, const uint8_t *data)
{
   uint_t i;
   uint32_t temp;

   //Pack the octet string into 9 words of 29 bits
   for(a[0] = 0, i = 0; i < 8; i++)
   {
      temp = LOAD32LE(data + i * 4);
      a[i] |= (temp << (i * 3)) & 0x1FFFFFFF;
      a[i + 1] = temp >> (29 - i * 3);
   }
}


/**
 * @brief Export an octet string
 * @param[in] a Pointer to the integer to be exported
 * @param[out] data Octet string resulting from the conversion
 **/

void curve25519Export(int32_t *a, uint8_t *data)
{
   uint_t i;
   uint32_t temp;

   //Unpack the 9 words of 29 bits
   for(i = 0; i < 8; i++)
   {
      temp = (a[i + 1] << (29 - i * 3)) | (a[i] >> (i * 3));
      STORE32LE(temp, data + i * 4);
   }
}

#endif
