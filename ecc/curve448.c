/**
 * @file curve448.c
 * @brief Curve448 elliptic curve (constant-time implementation)
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
#include "ecc/curve448.h"
#include "debug.h"

//Check crypto library configuration
#if (X448_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)


/**
 * @brief Set integer value
 * @param[out] a Pointer to the integer to be initialized
 * @param[in] b An integer such as 0 <= B < (2^28 - 1)
 **/

void curve448SetInt(int32_t *a, int32_t b)
{
   uint_t i;

   //Set the value of the least significant word
   a[0] = b;

   //Initialize the rest of the integer
   for(i = 1; i < 16; i++)
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

void curve448Add(int32_t *r, const int32_t *a, const int32_t *b)
{
#if (CURVE448_SPEED_OPTIMIZATION_LEVEL <= 1)
   uint_t i;
   int32_t temp;

   //Compute R = A + B
   for(temp = 0, i = 0; i < 16; i++)
   {
      temp += a[i] + b[i];
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += temp;
   r[8] += temp;
#else
   int32_t temp;

   //Compute R = A + B
   temp = a[0] + b[0];
   r[0] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[1] + b[1];
   r[1] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[2] + b[2];
   r[2] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[3] + b[3];
   r[3] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[4] + b[4];
   r[4] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[5] + b[5];
   r[5] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[6] + b[6];
   r[6] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[7] + b[7];
   r[7] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[8] + b[8];
   r[8] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[9] + b[9];
   r[9] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[10] + b[10];
   r[10] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[11] + b[11];
   r[11] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[12] + b[12];
   r[12] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[13] + b[13];
   r[13] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[14] + b[14];
   r[14] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[15] + b[15];
   r[15] = temp & 0x0FFFFFFF;
   temp >>= 28;

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += temp;
   r[8] += temp;
#endif
}


/**
 * @brief Modular addition
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^28 - 1)
 **/

void curve448AddInt(int32_t *r, const int32_t *a, int32_t b)
{
   uint_t i;
   int32_t temp;

   //Compute R = A + B
   for(temp = b, i = 0; i < 16; i++)
   {
      temp += a[i];
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += temp;
   r[8] += temp;
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve448Sub(int32_t *r, const int32_t *a, const int32_t *b)
{
#if (CURVE448_SPEED_OPTIMIZATION_LEVEL <= 1)
   uint_t i;
   int32_t temp;

   //Compute R = A - B
   for(temp = 0, i = 0; i < 16; i++)
   {
      temp += a[i] - b[i];
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += temp;
   r[8] += temp;
#else
   int32_t temp;

   //Compute R = A - B
   temp = a[0] - b[0];
   r[0] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[1] - b[1];
   r[1] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[2] - b[2];
   r[2] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[3] - b[3];
   r[3] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[4] - b[4];
   r[4] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[5] - b[5];
   r[5] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[6] - b[6];
   r[6] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[7] - b[7];
   r[7] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[8] - b[8];
   r[8] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[9] - b[9];
   r[9] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[10] - b[10];
   r[10] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[11] - b[11];
   r[11] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[12] - b[12];
   r[12] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[13] - b[13];
   r[13] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[14] - b[14];
   r[14] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += a[15] - b[15];
   r[15] = temp & 0x0FFFFFFF;
   temp >>= 28;

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += temp;
   r[8] += temp;
#endif
}


/**
 * @brief Modular subtraction
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^28 - 1)
 **/

void curve448SubInt(int32_t *r, const int32_t *a, int32_t b)
{
   uint_t i;
   int32_t temp;

   //Compute R = A - B
   for(temp = -b, i = 0; i < 16; i++)
   {
      temp += a[i];
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += temp;
   r[8] += temp;
}


/**
 * @brief 224-bit multiplication
 * @param[out] r Resulting integer R = A * B
 * @param[in] a An integer such as 0 <= A < (2^224 - 1)
 * @param[in] b An integer such as 0 <= B < (2^224 - 1)
 **/

void curve448Mul224(int32_t *r, const int32_t *a, const int32_t *b)
{
#if (CURVE448_SPEED_OPTIMIZATION_LEVEL == 0)
   uint_t i;
   uint_t j;
   int64_t acc;

   //Comba's method is used to perform multiplication
   for(acc = 0, i = 0; i < 16; i++)
   {
      //The algorithm computes the products, column by column
      if(i < 8)
      {
         //Inner loop
         for(j = 0; j <= i; j++)
         {
            acc += (int64_t) a[j] * b[i - j];
         }
      }
      else
      {
         //Inner loop
         for(j = i - 7; j < 8; j++)
         {
            acc += (int64_t) a[j] * b[i - j];
         }
      }

      //At the bottom of each column, the final result is written to memory
      r[i] = acc & 0x0FFFFFFF;
      //Propagate the carry upwards
      acc >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += (int32_t) acc;
   r[8] += (int32_t) acc;
#else
   int64_t acc;

   //Compute R = A * B
   acc = (int64_t) a[0] * b[0];
   r[0] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[0] * b[1];
   acc += (int64_t) a[1] * b[0];
   r[1] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[0] * b[2];
   acc += (int64_t) a[1] * b[1];
   acc += (int64_t) a[2] * b[0];
   r[2] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[0] * b[3];
   acc += (int64_t) a[1] * b[2];
   acc += (int64_t) a[2] * b[1];
   acc += (int64_t) a[3] * b[0];
   r[3] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[0] * b[4];
   acc += (int64_t) a[1] * b[3];
   acc += (int64_t) a[2] * b[2];
   acc += (int64_t) a[3] * b[1];
   acc += (int64_t) a[4] * b[0];
   r[4] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[0] * b[5];
   acc += (int64_t) a[1] * b[4];
   acc += (int64_t) a[2] * b[3];
   acc += (int64_t) a[3] * b[2];
   acc += (int64_t) a[4] * b[1];
   acc += (int64_t) a[5] * b[0];
   r[5] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[0] * b[6];
   acc += (int64_t) a[1] * b[5];
   acc += (int64_t) a[2] * b[4];
   acc += (int64_t) a[3] * b[3];
   acc += (int64_t) a[4] * b[2];
   acc += (int64_t) a[5] * b[1];
   acc += (int64_t) a[6] * b[0];
   r[6] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[0] * b[7];
   acc += (int64_t) a[1] * b[6];
   acc += (int64_t) a[2] * b[5];
   acc += (int64_t) a[3] * b[4];
   acc += (int64_t) a[4] * b[3];
   acc += (int64_t) a[5] * b[2];
   acc += (int64_t) a[6] * b[1];
   acc += (int64_t) a[7] * b[0];
   r[7] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[1] * b[7];
   acc += (int64_t) a[2] * b[6];
   acc += (int64_t) a[3] * b[5];
   acc += (int64_t) a[4] * b[4];
   acc += (int64_t) a[5] * b[3];
   acc += (int64_t) a[6] * b[2];
   acc += (int64_t) a[7] * b[1];
   r[8] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[2] * b[7];
   acc += (int64_t) a[3] * b[6];
   acc += (int64_t) a[4] * b[5];
   acc += (int64_t) a[5] * b[4];
   acc += (int64_t) a[6] * b[3];
   acc += (int64_t) a[7] * b[2];
   r[9] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[3] * b[7];
   acc += (int64_t) a[4] * b[6];
   acc += (int64_t) a[5] * b[5];
   acc += (int64_t) a[6] * b[4];
   acc += (int64_t) a[7] * b[3];
   r[10] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[4] * b[7];
   acc += (int64_t) a[5] * b[6];
   acc += (int64_t) a[6] * b[5];
   acc += (int64_t) a[7] * b[4];
   r[11] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[5] * b[7];
   acc += (int64_t) a[6] * b[6];
   acc += (int64_t) a[7] * b[5];
   r[12] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[6] * b[7];
   acc += (int64_t) a[7] * b[6];
   r[13] = acc & 0x0FFFFFFF;
   acc >>= 28;
   acc += (int64_t) a[7] * b[7];
   r[14] = acc & 0x0FFFFFFF;
   acc >>= 28;
   r[15] = acc & 0x0FFFFFFF;
   acc >>= 28;

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += (int32_t) acc;
   r[8] += (int32_t) acc;
#endif
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

__weak_func void curve448Mul(int32_t *r, const int32_t *a, const int32_t *b)
{
#if (CURVE448_SPEED_OPTIMIZATION_LEVEL == 0)
   uint_t i;
   uint_t j;
   int64_t acc1;
   int64_t acc2;
   int64_t acc3;
   int32_t aa[8];
   int32_t bb[8];
   int32_t u[16];

   //Let A = A0+(A1*w) and B = B0+(B1*w). Precompute AA = A0+A1 and BB = B0+B1
   for(i = 0; i < 8; i++)
   {
      aa[i] = a[i] + a[i + 8];
      bb[i] = b[i] + b[i + 8];
   }

   //Clear accumulators
   acc1 = 0;
   acc2 = 0;

   //Karatsuba multiplication can be fused with reduction mod p, and it doesn't
   //make the multiplication algorithm more complex
   for(i = 0; i < 8; i++)
   {
      //Compute the lower part of A1*B1, AA*BB and A0*B0
      for(acc3 = 0, j = 0; j <= i; j++)
      {
         acc1 += (int64_t) a[8 + j] * b[8 + i - j];
         acc2 += (int64_t) aa[j] * bb[i - j];
         acc3 += (int64_t) a[j] * b[i - j];
      }

      //Update accumulators
      acc1 += acc3;
      acc2 -= acc3;

      //Compute the upper part of A0*B0, A1*B1 and AA*BB
      for(acc3 = 0, j = i + 1; j < 8; j++)
      {
         acc1 -= (int64_t) a[j] * b[8 + i - j];
         acc2 += (int64_t) a[8 + j] * b[16 + i - j];
         acc3 += (int64_t) aa[j] * bb[8 + i - j];
      }

      //Update accumulators
      acc1 += acc3;
      acc2 += acc3;

      //The 2 columns are written to memory
      u[i] = (int32_t) acc1 & 0x0FFFFFFF;
      acc1 >>= 28;
      u[i + 8] = (int32_t) acc2 & 0x0FFFFFFF;
      acc2 >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   acc1 += acc2;

   //Propagate carries
   acc2 += u[0];
   u[0] = (int32_t) acc2 & 0x0FFFFFFF;
   acc2 >>= 28;
   u[1] += (int32_t) acc2;
   acc1 += u[8];
   u[8] = (int32_t) acc1 & 0x0FFFFFFF;
   acc1 >>= 28;
   u[9] += (int32_t) acc1;

   //Copy result
   curve448Copy(r, u);
#elif (CURVE448_SPEED_OPTIMIZATION_LEVEL == 1)
   uint_t i;
   int32_t c;
   int32_t temp;
   int32_t u[16];
   int32_t v[16];
   int32_t w[16];

   //Precompute A0+A1 and B0+B1
   for(temp = 0, i = 0; i < 8; i++)
   {
      u[i] = a[i] + a[i + 8];
      v[i] = b[i] + b[i + 8];
   }

   //Compute W = (A0+A1)*(B0+B1)
   curve448Mul224(w, u, v);
   //Compute U = A0*B0
   curve448Mul224(u, a, b);
   //Compute V = A1*B1
   curve448Mul224(v, a + 8, b + 8);

   //Karatsuba multiplication can be fused with reduction mod p, and it doesn't
   //make the multiplication algorithm more complex
   for(temp = 0, i = 0; i < 8; i++)
   {
      temp += u[i] - u[i + 8] + v[i] + w[i + 8];
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   for(i = 0; i < 8; i++)
   {
      temp += -u[i] + v[i + 8] + w[i] + w[i + 8];
      r[i + 8] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   c = temp;
   temp = r[0] + c;
   r[0] = temp & 0x0FFFFFFF;
   temp >>= 28;
   r[1] += temp;
   temp = r[8] + c;
   r[8] = temp & 0x0FFFFFFF;
   temp >>= 28;
   r[9] += temp;
#else
   int32_t c;
   int32_t temp;
   int32_t u[16];
   int32_t v[16];
   int32_t w[16];

   //Precompute A0+A1
   u[0] = a[0] + a[8];
   u[1] = a[1] + a[9];
   u[2] = a[2] + a[10];
   u[3] = a[3] + a[11];
   u[4] = a[4] + a[12];
   u[5] = a[5] + a[13];
   u[6] = a[6] + a[14];
   u[7] = a[7] + a[15];

   //Precompute B0+B1
   v[0] = b[0] + b[8];
   v[1] = b[1] + b[9];
   v[2] = b[2] + b[10];
   v[3] = b[3] + b[11];
   v[4] = b[4] + b[12];
   v[5] = b[5] + b[13];
   v[6] = b[6] + b[14];
   v[7] = b[7] + b[15];

   //Compute W = (A0+A1)*(B0+B1)
   curve448Mul224(w, u, v);
   //Compute U = A0*B0
   curve448Mul224(u, a, b);
   //Compute V = A1*B1
   curve448Mul224(v, a + 8, b + 8);

   //Karatsuba multiplication can be fused with reduction mod p, and it doesn't
   //make the multiplication algorithm more complex
   temp = u[0] - u[8] + v[0] + w[8];
   r[0] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += u[1] - u[9] + v[1] + w[9];
   r[1] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += u[2] - u[10] + v[2] + w[10];
   r[2] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += u[3] - u[11] + v[3] + w[11];
   r[3] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += u[4] - u[12] + v[4] + w[12];
   r[4] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += u[5] - u[13] + v[5] + w[13];
   r[5] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += u[6] - u[14] + v[6] + w[14];
   r[6] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += u[7] - u[15] + v[7] + w[15];
   r[7] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[0] + v[8] + w[0] + w[8];
   r[8] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[1] + v[9] + w[1] + w[9];
   r[9] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[2] + v[10] + w[2] + w[10];
   r[10] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[3] + v[11] + w[3] + w[11];
   r[11] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[4] + v[12] + w[4] + w[12];
   r[12] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[5] + v[13] + w[5] + w[13];
   r[13] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[6] + v[14] + w[6] + w[14];
   r[14] = temp & 0x0FFFFFFF;
   temp >>= 28;
   temp += -u[7] + v[15] + w[7] + w[15];
   r[15] = temp & 0x0FFFFFFF;
   temp >>= 28;

   //Perform modular reduction (2^448 = 2^224 + 1)
   c = temp;
   temp = r[0] + c;
   r[0] = temp & 0x0FFFFFFF;
   temp >>= 28;
   r[1] += temp;
   temp = r[8] + c;
   r[8] = temp & 0x0FFFFFFF;
   temp >>= 28;
   r[9] += temp;
#endif
}


/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < (2^28 - 1)
 **/

void curve448MulInt(int32_t *r, const int32_t *a, int32_t b)
{
   uint_t i;
   int64_t temp;

   //Compute R = A * B
   for(temp = 0, i = 0; i < 16; i++)
   {
      temp += (int64_t) a[i] * b;
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Perform modular reduction (2^448 = 2^224 + 1)
   r[0] += (int32_t) temp;
   r[8] += (int32_t) temp;
}


/**
 * @brief Modular squaring
 * @param[out] r Resulting integer R = (A ^ 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

__weak_func void curve448Sqr(int32_t *r, const int32_t *a)
{
   //Compute R = (A ^ 2) mod p
   curve448Mul(r, a, a);
}


/**
 * @brief Raise an integer to power 2^n
 * @param[out] r Resulting integer R = (A ^ (2^n)) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] n An integer such as n >= 1
 **/

void curve448Pwr2(int32_t *r, const int32_t *a, uint_t n)
{
   uint_t i;

   //Pre-compute (A ^ 2) mod p
   curve448Sqr(r, a);

   //Compute R = (A ^ (2^n)) mod p
   for(i = 1; i < n; i++)
   {
      curve448Sqr(r, r);
   }
}


/**
 * @brief Modular multiplicative inverse
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void curve448Inv(int32_t *r, const int32_t *a)
{
   int32_t u[16];
   int32_t v[16];

   //Since GF(p) is a prime field, the Fermat's little theorem can be
   //used to find the multiplicative inverse of A modulo p
   curve448Sqr(u, a);
   curve448Mul(u, u, a); //A^(2^2 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^3 - 1)
   curve448Pwr2(u, v, 3);
   curve448Mul(v, u, v); //A^(2^6 - 1)
   curve448Pwr2(u, v, 6);
   curve448Mul(u, u, v); //A^(2^12 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^13 - 1)
   curve448Pwr2(u, v, 13);
   curve448Mul(u, u, v); //A^(2^26 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^27 - 1)
   curve448Pwr2(u, v, 27);
   curve448Mul(u, u, v); //A^(2^54 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^55 - 1)
   curve448Pwr2(u, v, 55);
   curve448Mul(u, u, v); //A^(2^110 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, a); //A^(2^111 - 1)
   curve448Pwr2(u, v, 111);
   curve448Mul(v, u, v); //A^(2^222 - 1)
   curve448Sqr(u, v);
   curve448Mul(u, u, a); //A^(2^223 - 1)
   curve448Pwr2(u, u, 223);
   curve448Mul(u, u, v); //A^(2^446 - 2^222 - 1)
   curve448Sqr(u, u);
   curve448Sqr(u, u);
   curve448Mul(r, u, a); //A^(2^448 - 2^224 - 3)
}


/**
 * @brief Compute the square root of (A / B) modulo p
 * @param[out] r Resulting integer R = (A / B)^(1 / 2) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 < B < p
 * @return The function returns 0 if the square root exists, else 1
 **/

uint32_t curve448Sqrt(int32_t *r, const int32_t *a, const int32_t *b)
{
   uint32_t res;
   int32_t c[16];
   int32_t u[16];
   int32_t v[16];

   //Compute the candidate root (A / B)^((p + 1) / 4). This can be done
   //with the following trick, using a single modular powering for both the
   //inversion of B and the square root: A^3 * B * (A^5 * B^3)^((p - 3) / 4)
   curve448Sqr(u, a);
   curve448Sqr(u, u);
   curve448Mul(u, u, a);
   curve448Sqr(v, b);
   curve448Mul(v, v, b);

   //Compute C = A^5 * B^3
   curve448Mul(c, u, v);

   //Compute U = C^((p - 3) / 4)
   curve448Sqr(u, c);
   curve448Mul(u, u, c); //C^(2^2 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^3 - 1)
   curve448Pwr2(u, v, 3);
   curve448Mul(v, u, v); //C^(2^6 - 1)
   curve448Pwr2(u, v, 6);
   curve448Mul(u, u, v); //C^(2^12 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^13 - 1)
   curve448Pwr2(u, v, 13);
   curve448Mul(u, u, v); //C^(2^26 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^27 - 1)
   curve448Pwr2(u, v, 27);
   curve448Mul(u, u, v); //C^(2^54 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^55 - 1)
   curve448Pwr2(u, v, 55);
   curve448Mul(u, u, v); //C^(2^110 - 1)
   curve448Sqr(u, u);
   curve448Mul(v, u, c); //C^(2^111 - 1)
   curve448Pwr2(u, v, 111);
   curve448Mul(v, u, v); //C^(2^222 - 1)
   curve448Sqr(u, v);
   curve448Mul(u, u, c); //C^(2^223 - 1)
   curve448Pwr2(u, u, 223);
   curve448Mul(u, u, v); //C^(2^446 - 2^222 - 1)

   //The candidate root is U = A^3 * B * (A^5 * B^3)^((p - 3) / 4)
   curve448Sqr(v, a);
   curve448Mul(v, v, a);
   curve448Mul(u, u, v);
   curve448Mul(u, u, b);
   curve448Canonicalize(u, u);

   //Calculate C = B * U^2
   curve448Sqr(c, u);
   curve448Mul(c, c, b);
   curve448Canonicalize(c, c);

   //Reduce non-canonical values of A
   curve448Canonicalize(v, a);

   //Check whether B * U^2 = A
   res = curve448Comp(c, v);

   //Copy the candidate root
   curve448Copy(r, u);

   //Return 0 if the square root exists
   return res;
}


/**
 * @brief Reduce non-canonical value
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a An integer such as 0 <= A < (2^448 - 1)
 **/

void curve448Canonicalize(int32_t *r, const int32_t *a)
{
   uint_t i;
   int32_t temp;
   int32_t b[16];

   //Perform modular reduction (first pass)
   for(temp = 0, i = 0; i < 16; i++)
   {
      temp += a[i];
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Perform modular reduction (second pass)
   for(r[8] += temp, i = 0; i < 16; i++)
   {
      temp += r[i];
      r[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Compute B = A - (2^448 - 2^224 - 1)
   for(temp = 1, i = 0; i < 8; i++)
   {
      temp += r[i];
      b[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   for(temp += 1, i = 8; i < 16; i++)
   {
      temp += r[i];
      b[i] = temp & 0x0FFFFFFF;
      temp >>= 28;
   }

   //Compute the highest term of the result
   temp -= 1;

   //If B < (2^448 - 2^224 + 1) then R = B, else R = A
   curve448Select(r, b, r, temp & 1);
}


/**
 * @brief Copy an integer
 * @param[out] a Pointer to the destination integer
 * @param[in] b Pointer to the source integer
 **/

void curve448Copy(int32_t *a, const int32_t *b)
{
   uint_t i;

   //Copy the value of the integer
   for(i = 0; i < 16; i++)
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

void curve448Swap(int32_t *a, int32_t *b, uint32_t c)
{
   uint_t i;
   uint32_t mask;
   uint32_t dummy;

   //The mask is the all-1 or all-0 word
   mask = ~c + 1;

   //Conditional swap
   for(i = 0; i < 16; i++)
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

void curve448Select(int32_t *r, const int32_t *a, const int32_t *b,
   uint32_t c)
{
   uint_t i;
   uint32_t mask;

   //The mask is the all-1 or all-0 word
   mask = c - 1;

   //Select between A and B
   for(i = 0; i < 16; i++)
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

uint32_t curve448Comp(const int32_t *a, const int32_t *b)
{
   uint_t i;
   uint32_t mask;

   //Initialize mask
   mask = 0;

   //Compare A and B
   for(i = 0; i < 16; i++)
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

void curve448Import(int32_t *a, const uint8_t *data)
{
   uint_t i;
   uint32_t temp;

   //Pack the octet string into 16 words of 28 bits
   for(a[0] = 0, i = 0; i < 7; i++)
   {
      temp = LOAD32LE(data + i * 4);
      a[i] |= (temp << (i * 4)) & 0x0FFFFFFF;
      a[i + 1] = temp >> (28 - i * 4);
   }

   for(a[8] = 0, i = 0; i < 7; i++)
   {
      temp = LOAD32LE(data + (i + 7) * 4);
      a[i + 8] |= (temp << (i * 4)) & 0x0FFFFFFF;
      a[i + 9] = temp >> (28 - i * 4);
   }
}


/**
 * @brief Export an octet string
 * @param[in] a Pointer to the integer to be exported
 * @param[out] data Octet string resulting from the conversion
 **/

void curve448Export(int32_t *a, uint8_t *data)
{
   uint_t i;
   uint32_t temp;

   //Unpack the 16 words of 28 bits
   for(i = 0; i < 7; i++)
   {
      temp = (a[i + 1] << (28 - i * 4)) | (a[i] >> (i * 4));
      STORE32LE(temp, data + i * 4);
   }

   for(i = 0; i < 7; i++)
   {
      temp = (a[i + 9] << (28 - 4 * i)) | (a[i + 8] >> (i * 4));
      STORE32LE(temp, data + (i + 7) * 4);
   }
}

#endif
