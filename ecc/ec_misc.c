/**
 * @file ec_misc.c
 * @brief Helper routines for ECC
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
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (EC_SUPPORT == ENABLED)


/**
 * @brief Octet string to integer conversion
 * @param[out] r Integer resulting from the conversion
 * @param[in] n Size of the integer, in words
 * @param[in] input Octet string to be converted
 * @param[in] length Length of the octet string
 * @param[in] format Input format
 * @return Error code
 **/

error_t ecScalarImport(uint32_t *r, uint_t n, const uint8_t *input,
   size_t length, EcScalarFormat format)
{
   error_t error;
   uint_t i;
   uint32_t temp;

   //Initialize status code
   error = NO_ERROR;

   //Check input format
   if(format == EC_SCALAR_FORMAT_LITTLE_ENDIAN)
   {
      //Skip trailing zeroes
      while(length > 0 && input[length - 1] == 0)
      {
         length--;
      }

      //Make sure the integer is large enough
      if(length <= (n * 4))
      {
         //Clear the contents of the integer
         for(i = 0; i < n; i++)
         {
            r[i] = 0;
         }

         //Import data
         for(i = 0; i < length; i++, input++)
         {
            temp = *input & 0xFF;
            r[i / 4] |= temp << ((i % 4) * 8);
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
   else if(format == EC_SCALAR_FORMAT_BIG_ENDIAN)
   {
      //Skip leading zeroes
      while(length > 1 && *input == 0)
      {
         input++;
         length--;
      }

      //Make sure the integer is large enough
      if(length <= (n * 4))
      {
         //Clear the contents of the integer
         for(i = 0; i < n; i++)
         {
            r[i] = 0;
         }

         //Start from the least significant byte
         input += length - 1;

         //Import data
         for(i = 0; i < length; i++, input--)
         {
            temp = *input & 0xFF;
            r[i / 4] |= temp << ((i % 4) * 8);
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Integer to octet string conversion
 * @param[in] a Integer to be converted
 * @param[in] n Size of the integer, in words
 * @param[out] output Octet string resulting from the conversion
 * @param[in] length Intended length of the resulting octet string
 * @param[in] format Output format
 * @return Error code
 **/

error_t ecScalarExport(const uint32_t *a, uint_t n, uint8_t *output,
   size_t length, EcScalarFormat format)
{
   error_t error;
   uint_t i;
   uint_t k;
   uint32_t temp;

   //Initialize status code
   error = NO_ERROR;

   //Check input format
   if(format == EC_SCALAR_FORMAT_LITTLE_ENDIAN)
   {
      //Get the actual length in bytes
      k = ecScalarGetByteLength(a, n);

      //Make sure the output buffer is large enough
      if(k <= length)
      {
         //Clear output buffer
         osMemset(output, 0, length);

         //Export data
         for(i = 0; i < k; i++, output++)
         {
            temp = a[i / 4] >> ((i % 4) * 8);
            *output = temp & 0xFF;
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
   else if(format == EC_SCALAR_FORMAT_BIG_ENDIAN)
   {
      //Get the actual length in bytes
      k = ecScalarGetByteLength(a, n);

      //Make sure the output buffer is large enough
      if(k <= length)
      {
         //Clear output buffer
         osMemset(output, 0, length);

         //Point to the least significant word
         output += length - 1;

         //Export data
         for(i = 0; i < k; i++, output--)
         {
            temp = a[i / 4] >> ((i % 4) * 8);
            *output = temp & 0xFF;
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the actual length in bytes
 * @param[in] a Pointer to an integer
 * @param[in] n Size of the integer, in words
 * @return The actual byte count
 **/

uint_t ecScalarGetByteLength(const uint32_t *a, uint_t n)
{
   uint_t k;
   uint32_t m;

   //Check the size of the integer
   if(n == 0)
      return 0;

   //Start from the most significant word
   for(k = n - 1; k > 0; k--)
   {
      //Loop as long as the current word is zero
      if(a[k] != 0)
      {
         break;
      }
   }

   //Get the current word
   m = a[k];
   //Convert the length to a byte count
   k *= 4;

   //Adjust the byte count
   for(; m != 0; m >>= 8)
   {
      k++;
   }

   //Return the actual length in bytes
   return k;
}


/**
 * @brief Get the actual length in bits
 * @param[in] a Pointer to an integer
 * @param[in] n Size of the integer, in words
 * @return The actual bit count
 **/

uint_t ecScalarGetBitLength(const uint32_t *a, uint_t n)
{
   uint_t k;
   uint32_t m;

   //Check the size of the integer
   if(n == 0)
      return 0;

   //Start from the most significant word
   for(k = n - 1; k > 0; k--)
   {
      //Loop as long as the current word is zero
      if(a[k] != 0)
      {
         break;
      }
   }

   //Get the current word
   m = a[k];
   //Convert the length to a bit count
   k *= 32;

   //Adjust the bit count
   for(; m != 0; m >>= 1)
   {
      k++;
   }

   //Return the actual length in bits
   return k;
}


/**
 * @brief Get the bit value at the specified index
 * @param[in] a Pointer to an integer
 * @param[in] index Position where to read the bit
 * @return The actual bit value
 **/

uint32_t ecScalarGetBitValue(const uint32_t *a, int_t index)
{
   //Valid index?
   if(index >= 0)
   {
      return (a[index / 32] >> (index % 32)) & 1;
   }
   else
   {
      return 0;
   }
}


/**
 * @brief Compare integers
 * @param[in] a Pointer to the first integer
 * @param[in] b Pointer to the second integer
 * @param[in] n Size of the integers, in words
 * @return Comparison result
 **/

int_t ecScalarComp(const uint32_t *a, const uint32_t *b, uint_t n)
{
   int_t i;
   int_t res;

   //Initialize variable
   res = 0;

   //Compare A and B
   for(i = n - 1; i >= 0 && res == 0; i--)
   {
      if(a[i] > b[i])
      {
         res = 1;
      }
      else if(a[i] < b[i])
      {
         res = -1;
      }
      else
      {
      }
   }

   //Return comparison result
   return res;
}


/**
 * @brief Compare integers
 * @param[in] a Pointer to the first integer
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 * @param[in] n Size of the integers, in words
 * @return Comparison result
 **/

int_t ecScalarCompInt(const uint32_t *a, uint32_t b, uint_t n)
{
   int_t i;
   int_t res;

   //Initialize variable
   res = 0;

   //Compare the upper words
   for(i = n - 1; i > 0 && res == 0; i--)
   {
      if(a[i] > 0)
      {
         res = 1;
      }
   }

   //Compare the lower word
   if(res == 0)
   {
      if(a[0] > b)
      {
         res = 1;
      }
      else if(a[0] < b)
      {
         res = -1;
      }
      else
      {
      }
   }

   //Return comparison result
   return res;
}


/**
 * @brief Test if two integers are equal
 * @param[in] a Pointer to the first integer
 * @param[in] b Pointer to the second integer
 * @param[in] n Size of the integers, in words
 * @return The function returns 1 if the A = B, else 0
 **/

uint32_t ecScalarTestEqual(const uint32_t *a, const uint32_t *b, uint_t n)
{
   //Perform comparison
   return ecScalarTestNotEqual(a, b, n) ^ 1;
}


/**
 * @brief Test if two integers are equal
 * @param[in] a Pointer to the first integer
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 * @param[in] n Size of the integers, in words
 * @return The function returns 1 if the A = B, else 0
 **/

uint32_t ecScalarTestEqualInt(const uint32_t *a, uint32_t b, uint_t n)
{
   //Perform comparison
   return ecScalarTestNotEqualInt(a, b, n) ^ 1;
}


/**
 * @brief Test if two integers are different
 * @param[in] a Pointer to the first integer
 * @param[in] b Pointer to the second integer
 * @param[in] n Size of the integers, in words
 * @return The function returns 1 if the A != B, else 0
 **/

uint32_t ecScalarTestNotEqual(const uint32_t *a, const uint32_t *b, uint_t n)
{
   uint_t i;
   uint32_t mask;

   //Initialize mask
   mask = 0;

   //Compare A and B
   for(i = 0; i < n; i++)
   {
      //Constant time implementation
      mask |= a[i] ^ b[i];
   }

   //Return 1 if A != B, else 0
   return ((uint32_t) (mask | (~mask + 1))) >> 31;
}


/**
 * @brief Test if two integers are different
 * @param[in] a Pointer to the first integer
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 * @param[in] n Size of the integers, in words
 * @return The function returns 1 if the A != B, else 0
 **/

uint32_t ecScalarTestNotEqualInt(const uint32_t *a, uint32_t b, uint_t n)
{
   uint_t i;
   uint32_t mask;

   //Initialize mask
   mask = a[0] ^ b;

   //Compare A and B
   for(i = 1; i < n; i++)
   {
      //Constant time implementation
      mask |= a[i];
   }

   //Return 1 if A != B, else 0
   return ((uint32_t) (mask | (~mask + 1))) >> 31;
}


/**
 * @brief Set integer value
 * @param[out] a Pointer to the integer to be initialized
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 * @param[in] n Size of the integer A, in words
 **/

void ecScalarSetInt(uint32_t *a, uint32_t b, uint_t n)
{
   uint_t i;

   //Set the value of the least significant word
   a[0] = b;

   //Initialize the rest of the integer
   for(i = 1; i < n; i++)
   {
      a[i] = 0;
   }
}


/**
 * @brief Copy an integer
 * @param[out] a Pointer to the destination integer
 * @param[in] b Pointer to the source integer
 * @param[in] n Size of the integers, in words
 **/

void ecScalarCopy(uint32_t *a, const uint32_t *b, uint_t n)
{
   uint_t i;

   //Copy the value of the integer
   for(i = 0; i < n; i++)
   {
      a[i] = b[i];
   }
}


/**
 * @brief Conditional swap
 * @param[in,out] a Pointer to the first integer
 * @param[in,out] b Pointer to the second integer
 * @param[in] c Condition variable
 * @param[in] n Size of the integers, in words
 **/

void ecScalarSwap(uint32_t *a, uint32_t *b, uint32_t c, uint_t n)
{
   uint_t i;
   uint32_t mask;
   uint32_t dummy;

   //The mask is the all-1 or all-0 word
   mask = ~c + 1;

   //Conditional swap
   for(i = 0; i < n; i++)
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
 * @param[in] n Size of the integers, in words
 **/

void ecScalarSelect(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c, uint_t n)
{
   uint_t i;
   uint32_t mask;

   //The mask is the all-1 or all-0 word
   mask = c - 1;

   //Select between A and B
   for(i = 0; i < n; i++)
   {
      //Constant time implementation
      r[i] = (a[i] & mask) | (b[i] & ~mask);
   }
}


/**
 * @brief Generate a random value
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Random integer in range such as 1 < R < q - 1
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t ecScalarRand(const EcCurve *curve, uint32_t *r,
   const PrngAlgo *prngAlgo, void *prngContext)
{
   error_t error;
   uint_t n;
   uint32_t a[EC_MAX_ORDER_SIZE];
   uint32_t t[EC_MAX_ORDER_SIZE + 2];

   //Check parameters
   if(prngAlgo != NULL && prngContext != NULL)
   {
      //Get the length of the order, in words
      n = (curve->orderSize + 31) / 32;

      //Generate extra random bits so that the bias produced by the modular
      //reduction is negligible
      error = prngAlgo->generate(prngContext, (uint8_t *) t,
         (n + 2) * sizeof(uint32_t));

      //Check status code
      if(!error)
      {
         //Compute r = (t mod (q - 2)) + 1
         ecScalarSubInt(a, curve->q, 2, n);
         ecScalarMod(r, t, n + 2, a, n);
         ecScalarAddInt(r, r, 1, n);
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Addition of two integers
 * @param[out] r Resulting integer R = A + B
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] b An integer such as 0 <= B < (2^32)^n
 * @param[in] n Size of the operands, in words
 * @return Value of the carry bit
 **/

uint32_t ecScalarAdd(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint_t n)
{
   uint_t i;
   uint64_t temp;

   //Compute R = A + B
   for(temp = 0, i = 0; i < n; i++)
   {
      temp += a[i];
      temp += b[i];
      r[i] = (uint32_t) temp;
      temp >>= 32;
   }

   //Return the value of the carry bit
   return temp & 1;
}


/**
 * @brief Addition of two integers
 * @param[out] r Resulting integer R = A + B
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 * @param[in] n Size of the operands, in words
 * @return Value of the carry bit
 **/

uint32_t ecScalarAddInt(uint32_t *r, const uint32_t *a, uint32_t b, uint_t n)
{
   uint_t i;
   uint64_t temp;

   //Compute R = A + B
   for(temp = b, i = 0; i < n; i++)
   {
      temp += a[i];
      r[i] = (uint32_t) temp;
      temp >>= 32;
   }

   //Return the value of the carry bit
   return temp & 1;
}


/**
 * @brief Subtraction of two integers
 * @param[out] r Resulting integer R = A - B
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] b An integer such as 0 <= B < (2^32)^n
 * @param[in] n Size of the operands, in words
 * @return 1 if the result is negative, else 0
 **/

uint32_t ecScalarSub(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint_t n)
{
   uint_t i;
   int64_t temp;

   //Compute R = A - B
   for(temp = 0, i = 0; i < n; i++)
   {
      temp += a[i];
      temp -= b[i];
      r[i] = (uint32_t) temp;
      temp >>= 32;
   }

   //Return 1 if the result of the subtraction is negative
   return temp & 1;
}


/**
 * @brief Subtraction of two integers
 * @param[out] r Resulting integer R = A - B
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] b An integer such as 0 <= B < (2^32 - 1)
 * @param[in] n Size of the operands, in words
 * @return 1 if the result is negative, else 0
 **/

uint32_t ecScalarSubInt(uint32_t *r, const uint32_t *a, uint32_t b, uint_t n)
{
   uint_t i;
   int64_t temp;

   //Initialize variable
   temp = b;

   //Compute R = A - B
   for(temp = -temp, i = 0; i < n; i++)
   {
      temp += a[i];
      r[i] = (uint32_t) temp;
      temp >>= 32;
   }

   //Return 1 if the result of the subtraction is negative
   return temp & 1;
}


/**
 * @brief Multiplication of two integers
 * @param[out] rl Low part of the result R = (A * B) mod (2^32)^n
 * @param[out] rh High part of the result R = (A * B) / (2^32)^n
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] b An integer such as 0 <= B < (2^32)^n
 * @param[in] n Size of the operands, in words
 **/

__weak_func void ecScalarMul(uint32_t *rl, uint32_t *rh, const uint32_t *a,
   const uint32_t *b, uint_t n)
{
   uint_t i;
   uint_t j;
   uint64_t c;
   uint64_t temp;

   //Initialize variables
   temp = 0;
   c = 0;

   //Compute the low part of the multiplication
   for(i = 0; i < n; i++)
   {
      //The Comba's algorithm computes the products, column by column
      for(j = 0; j <= i; j++)
      {
         temp += (uint64_t) a[j] * b[i - j];
         c += temp >> 32;
         temp &= 0xFFFFFFFF;
      }

      //At the bottom of each column, the final result is written to memory
      if(rl != NULL)
      {
         rl[i] = temp & 0xFFFFFFFF;
      }

      //Propagate the carry upwards
      temp = c & 0xFFFFFFFF;
      c >>= 32;
   }

   //Check whether the high part of the multiplication should be calculated
   if(rh != NULL)
   {
      //Compute the high part of the multiplication
      for(i = n; i < (2 * n); i++)
      {
         //The Comba's algorithm computes the products, column by column
         for(j = i + 1 - n; j < n; j++)
         {
            temp += (uint64_t) a[j] * b[i - j];
            c += temp >> 32;
            temp &= 0xFFFFFFFF;
         }

         //At the bottom of each column, the final result is written to memory
         rh[i - n] = (uint32_t) temp;

         //Propagate the carry upwards
         temp = c & 0xFFFFFFFF;
         c >>= 32;
      }
   }
}


/**
 * @brief Squaring operation
 * @param[out] r Result R = A ^ 2
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] n Size of the integer A, in words
 **/

__weak_func void ecScalarSqr(uint32_t *r, const uint32_t *a, uint_t n)
{
   uint_t i;
   uint_t j;
   uint64_t b;
   uint64_t c;
   uint64_t temp;

   //Initialize variables
   temp = 0;
   c = 0;

   //Comba's method is used to perform multiplication
   for(i = 0; i < (2 * n); i++)
   {
      //Calculate lower bound
      j = (i < n) ? 0 : (i + 1 - n);

      //The algorithm computes the products, column by column
      for(; j <= i && j <= (i - j); j++)
      {
         b = (uint64_t) a[j] * a[i - j];
         temp += b;
         c += temp >> 32;
         temp &= 0xFFFFFFFF;

         if(j < (i - j))
         {
            temp += b;
            c += temp >> 32;
            temp &= 0xFFFFFFFF;
         }
      }

      //At the bottom of each column, the final result is written to memory
      r[i] = temp & 0xFFFFFFFF;

      //Propagate the carry upwards
      temp = c & 0xFFFFFFFF;
      c >>= 32;
   }
}


/**
 * @brief Left shift operation
 * @param[out] r Result R = A << k
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] k The number of bits to shift
 * @param[in] n Size of the integer A, in words
 **/

void ecScalarShiftLeft(uint32_t *r, const uint32_t *a, uint_t k, uint_t n)
{
   uint_t i;

   //Number of 32-bit words to shift
   uint_t k1 = k / 32;
   //Number of bits to shift
   uint_t k2 = k % 32;

   //First, shift words
   if(k1 > 0)
   {
      //Process the most significant words
      for(i = n - 1; i >= k1; i--)
      {
         r[i] = a[i - k1];
      }

      //Fill the rest with zeroes
      for(i = 0; i < k1; i++)
      {
         r[i] = 0;
      }
   }
   else
   {
      //Copy words
      for(i = 0; i < n; i++)
      {
         r[i] = a[i];
      }
   }

   //Then shift bits
   if(k2 > 0)
   {
      //Process the most significant words
      for(i = n - 1; i >= 1; i--)
      {
         r[i] = (r[i] << k2) | (r[i - 1] >> (32 - k2));
      }

      //The least significant word requires a special handling
      r[0] <<= k2;
   }
}


/**
 * @brief Right shift operation
 * @param[out] r Result R = A >> k
 * @param[in] a An integer such as 0 <= A < (2^32)^n
 * @param[in] k The number of bits to shift
 * @param[in] n Size of the integer A, in words
 **/

void ecScalarShiftRight(uint32_t *r, const uint32_t *a, uint_t k, uint_t n)
{
   uint_t i;

   //Number of 32-bit words to shift
   uint_t k1 = k / 32;
   //Number of bits to shift
   uint_t k2 = k % 32;

   //Check parameters
   if(k1 >= n)
   {
      //Clear words
      for(i = 0; i < n; i++)
      {
         r[i] = 0;
      }
   }
   else
   {
      //First, shift words
      if(k1 > 0)
      {
         //Process the least significant words
         for(i = 0; i < (n - k1); i++)
         {
            r[i] = a[i + k1];
         }

         //Fill the rest with zeroes
         for(i = n - k1; i < n; i++)
         {
            r[i] = 0;
         }
      }
      else
      {
         //Copy words
         for(i = 0; i < n; i++)
         {
            r[i] = a[i];
         }
      }

      //Then shift bits
      if(k2 > 0)
      {
         //Process the least significant words
         for(i = 0; i < (n - k1 - 1); i++)
         {
            r[i] = (r[i] >> k2) | (r[i + 1] << (32 - k2));
         }

         //The most significant word requires a special handling
         r[i] >>= k2;
      }
   }
}


/**
 * @brief Modulo operation
 * @param[out] r Resulting integer R = A mod P
 * @param[in] a An integer such as 0 <= A < (2^32)^m
 * @param[in] m Size of integer A, in words
 * @param[in] p An integer such as 0 <= P < (2^32)^n
 * @param[in] n Size of integers P and R, in words
 **/

void ecScalarMod(uint32_t *r, const uint32_t *a, uint_t m, const uint32_t *p,
   uint_t n)
{
   uint_t i;
   uint_t k;
   uint32_t c;
   uint32_t u[EC_MAX_ORDER_SIZE + 2];
   uint32_t v[EC_MAX_ORDER_SIZE + 2];
   uint32_t w[EC_MAX_ORDER_SIZE + 2];

   //Get the length of P, in bits
   k = ecScalarGetBitLength(p, n);

   //Check the length of P
   if(k <= (m * 32))
   {
      //Set U = A
      ecScalarSetInt(u, 0, m);
      ecScalarCopy(u, a, m);

      //Pad P with zeroes on the right
      ecScalarSetInt(v, 0, m);
      ecScalarCopy(v, p, n);
      ecScalarShiftLeft(v, v, (m * 32) - k, m);

      //Compute R = A mod P
      for(i = 0; i <= (m * 32) - k; i++)
      {
         c = ecScalarSub(w, u, v, m);
         ecScalarSelect(u, w, u, c, m);
         ecScalarShiftRight(v, v, 1, m);
      }

      //Copy the resulting integer
      ecScalarCopy(r, u, n);
   }
   else
   {
      //Set R = A
      ecScalarSetInt(r, 0, n);
      ecScalarCopy(r, a, m);
   }
}


/**
 * @brief Modular addition
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A + B) mod q
 * @param[in] a An integer such as 0 <= A < q
 * @param[in] b An integer such as 0 <= B < q
 **/

void ecScalarAddMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b)
{
   uint_t qLen;
   uint32_t c;
   uint32_t u[EC_MAX_ORDER_SIZE + 1];
   uint32_t v[EC_MAX_ORDER_SIZE + 1];

   //Get the length of the order, in words
   qLen = (curve->orderSize + 31) / 32;

   //Compute R = (A + B) mod q
   u[qLen] = ecScalarAdd(u, a, b, qLen);
   c = ecScalarSub(v, u, curve->q, qLen + 1);
   ecScalarSelect(r, v, u, c, qLen);
}


/**
 * @brief Modular subtraction
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A - B) mod q
 * @param[in] a An integer such as 0 <= A < q
 * @param[in] b An integer such as 0 <= B < q
 **/

void ecScalarSubMod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   const uint32_t *b)
{
   uint_t qLen;
   uint32_t c;
   uint32_t u[EC_MAX_ORDER_SIZE];

   //Get the length of the order, in words
   qLen = (curve->orderSize + 31) / 32;

   //Compute R = (A - B) mod q
   c = ecScalarSub(r, a, b, qLen);
   ecScalarAdd(u, r, curve->q, qLen);
   ecScalarSelect(r, r, u, c, qLen);
}


/**
 * @brief Modular multiplication
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A * B) mod q
 * @param[in] a An integer such as 0 <= A < q
 * @param[in] b An integer such as 0 <= B < q
 **/

__weak_func void ecScalarMulMod(const EcCurve *curve, uint32_t *r,
   const uint32_t *a, const uint32_t *b)
{
   uint_t qLen;
   uint32_t u[EC_MAX_ORDER_SIZE * 2];

   //Get the length of the order, in words
   qLen = (curve->orderSize + 31) / 32;

   //Compute R = (A * B) mod q
   ecScalarMul(u, u + qLen, a, b, qLen);
   curve->scalarMod(curve, r, u);
}


/**
 * @brief Modular squaring
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^2 mod q
 * @param[in] a An integer such as 0 <= A < q
 **/

__weak_func void ecScalarSqrMod(const EcCurve *curve, uint32_t *r,
   const uint32_t *a)
{
   uint_t qLen;
   uint32_t u[EC_MAX_ORDER_SIZE * 2];

   //Get the length of the order, in words
   qLen = (curve->orderSize + 31) / 32;

   //Compute R = (A ^ 2) mod q
   ecScalarSqr(u, a, qLen);
   curve->scalarMod(curve, r, u);
}


/**
 * @brief Raise an integer to power 2^n
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A ^ (2^n)) mod q
 * @param[in] a An integer such as 0 <= A < q
 * @param[in] n An integer such as n >= 1
 **/

void ecScalarPwr2Mod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   uint_t n)
{
   uint_t i;

   //Pre-compute (A ^ 2) mod q
   ecScalarSqrMod(curve, r, a);

   //Compute R = (A ^ (2^n)) mod q
   for(i = 1; i < n; i++)
   {
      ecScalarSqrMod(curve, r, r);
   }
}


/**
 * @brief Modular inversion
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod q
 * @param[in] a An integer such as 0 <= A < q
 **/

void ecScalarInvMod(const EcCurve *curve, uint32_t *r,
   const uint32_t *a)
{
   //Curve-specific implementation?
   if(curve->scalarInv != NULL)
   {
      //Compute R = A^-1 mod q
      curve->scalarInv(curve, r, a);
   }
   else
   {
      int_t i;
      uint_t qLen;
      uint32_t q[EC_MAX_ORDER_SIZE];
      uint32_t u[EC_MAX_ORDER_SIZE];

      //Get the length of the order, in words
      qLen = (curve->orderSize + 31) / 32;

      //Pre-compute q' = q - 2
      ecScalarSubInt(q, curve->q, 2, qLen);

      //Let U = 1
      ecScalarSetInt(u, 1, qLen);

      //Since q is prime, the multiplicative inverse of A modulo p can be found
      //using Fermat's little theorem
      for(i = curve->orderSize - 1; i >= 0; i--)
      {
         //Calculate U = U^2
         ecScalarSqrMod(curve, u, u);

         //Check the value of q'(i)
         if(((q[i / 32] >> (i % 32)) & 1) != 0)
         {
            //Calculate U = U * A
            ecScalarMulMod(curve, u, u, a);
         }
      }

      //Copy the resulting value
      ecScalarCopy(r, u, qLen);
   }
}


/**
 * @brief Modular addition
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A + B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

__weak_func void ecFieldAddMod(const EcCurve *curve, uint32_t *r,
   const uint32_t *a, const uint32_t *b)
{
   uint_t pLen;
   uint32_t c;
   uint32_t u[EC_MAX_MODULUS_SIZE + 1];
   uint32_t v[EC_MAX_MODULUS_SIZE + 1];

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Compute R = (A + B) mod p
   u[pLen] = ecScalarAdd(u, a, b, pLen);
   c = ecScalarSub(v, u, curve->p, pLen + 1);
   ecScalarSelect(r, v, u, c, pLen);
}


/**
 * @brief Modular subtraction
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A - B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

__weak_func void ecFieldSubMod(const EcCurve *curve, uint32_t *r,
   const uint32_t *a, const uint32_t *b)
{
   uint_t pLen;
   uint32_t c;
   uint32_t u[EC_MAX_MODULUS_SIZE];

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Compute R = (A - B) mod p
   c = ecScalarSub(r, a, b, pLen);
   ecScalarAdd(u, r, curve->p, pLen);
   ecScalarSelect(r, r, u, c, pLen);
}


/**
 * @brief Modular multiplication
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

__weak_func void ecFieldMulMod(const EcCurve *curve, uint32_t *r,
   const uint32_t *a, const uint32_t *b)
{
   uint_t pLen;
   uint32_t u[EC_MAX_MODULUS_SIZE * 2];

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Compute R = (A * B) mod p
   ecScalarMul(u, u + pLen, a, b, pLen);
   curve->fieldMod(curve, r, u);
}


/**
 * @brief Modular squaring
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^2 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

__weak_func void ecFieldSqrMod(const EcCurve *curve, uint32_t *r,
   const uint32_t *a)
{
   uint_t pLen;
   uint32_t u[EC_MAX_MODULUS_SIZE * 2];

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Compute R = (A ^ 2) mod p
   ecScalarSqr(u, a, pLen);
   curve->fieldMod(curve, r, u);
}


/**
 * @brief Raise an integer to power 2^n
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = (A ^ (2^n)) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] n An integer such as n >= 1
 **/

void ecFieldPwr2Mod(const EcCurve *curve, uint32_t *r, const uint32_t *a,
   uint_t n)
{
   uint_t i;

   //Pre-compute (A ^ 2) mod p
   ecFieldSqrMod(curve, r, a);

   //Compute R = (A ^ (2^n)) mod p
   for(i = 1; i < n; i++)
   {
      ecFieldSqrMod(curve, r, r);
   }
}


/**
 * @brief Modular inversion
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A^-1 mod p
 * @param[in] a An integer such as 0 <= A < p
 **/

void ecFieldInvMod(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   //Curve-specific implementation?
   if(curve->fieldInv != NULL)
   {
      //Compute R = A^-1 mod p
      curve->fieldInv(curve, r, a);
   }
   else
   {
      int_t i;
      uint_t pLen;
      uint32_t p[EC_MAX_MODULUS_SIZE];
      uint32_t u[EC_MAX_MODULUS_SIZE];

      //Get the length of the modulus, in words
      pLen = (curve->fieldSize + 31) / 32;

      //Pre-compute p' = p - 2
      ecScalarSubInt(p, curve->p, 2, pLen);

      //Let U = 1
      ecScalarSetInt(u, 1, pLen);

      //Since p is prime, the multiplicative inverse of A modulo p can be found
      //using Fermat's little theorem
      for(i = curve->fieldSize - 1; i >= 0; i--)
      {
         //Calculate U = U^2
         ecFieldSqrMod(curve, u, u);

         //Check the value of p'(i)
         if(((p[i / 32] >> (i % 32)) & 1) != 0)
         {
            ecFieldMulMod(curve, u, u, a);
         }
      }

      //Copy the resulting value
      ecScalarCopy(r, u, pLen);
   }
}


/**
 * @brief Reduce non-canonical value
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting integer R = A mod p
 * @param[in] a Input integer
 **/

void ecFieldCanonicalize(const EcCurve *curve, uint32_t *r, const uint32_t *a)
{
   uint_t pLen;
   uint32_t c;
   uint32_t b[EC_MAX_MODULUS_SIZE];

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Compute R = A mod p
   c = ecScalarSub(b, a, curve->p, pLen);
   ecScalarSelect(r, b, a, c, pLen);
}


/**
 * @brief An auxiliary function for the twin multiplication
 * @param[in] t An integer T such as 0 <= T <= 31
 * @return Output value
 **/

uint_t ecTwinMulF(uint_t t)
{
   uint_t h;

   //Check the value of T
   if(18 <= t && t < 22)
   {
      h = 9;
   }
   else if(14 <= t && t < 18)
   {
      h = 10;
   }
   else if(22 <= t && t < 24)
   {
      h = 11;
   }
   else if(4 <= t && t < 12)
   {
      h = 14;
   }
   else
   {
      h = 12;
   }

   //Return value
   return h;
}


/**
 * @brief Co-Z addition with update
 * @param[in] state Pointer to the working state
 * @param[out] r Output integer R
 * @param[out] s Output integer S
 * @param[in] p Output integer P
 * @param[in] q Output integer Q
 **/

void ecZaddu(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p,
   const EcPoint3 *q)
{
   uint_t pLen;

   //Get the length of the modulus, in words
   pLen = (state->curve->fieldSize + 31) / 32;

   //T1 = X1
   ecScalarCopy(state->t1, p->x, pLen);
   //T2 = Y1
   ecScalarCopy(state->t2, p->y, pLen);
   //T3 = Z
   ecScalarCopy(state->t3, p->z, pLen);
   //T4 = X2
   ecScalarCopy(state->t4, q->x, pLen);
   //T5 = Y2
   ecScalarCopy(state->t5, q->y, pLen);

   //1. T6 = T1 - T4
   ecFieldSubMod(state->curve, state->t6, state->t1, state->t4);
   //2. T3 = T3 * T6
   ecFieldMulMod(state->curve, state->t3, state->t3, state->t6);
   //3. T6 = T6 ^ 2
   ecFieldSqrMod(state->curve, state->t6, state->t6);
   //4. T1 = T1 * T6
   ecFieldMulMod(state->curve, state->t1, state->t1, state->t6);
   //5. T6 = T6 * T4
   ecFieldMulMod(state->curve, state->t6, state->t6, state->t4);
   //6. T5 = T2 - T5
   ecFieldSubMod(state->curve, state->t5, state->t2, state->t5);
   //7. T4 = T5 ^ 2
   ecFieldSqrMod(state->curve, state->t4, state->t5);
   //8. T4 = T4 - T1
   ecFieldSubMod(state->curve, state->t4, state->t4, state->t1);
   //9. T4 = T4 - T6
   ecFieldSubMod(state->curve, state->t4, state->t4, state->t6);
   //10. T6 = T1 - T6
   ecFieldSubMod(state->curve, state->t6, state->t1, state->t6);
   //11. T2 = T2 * T6
   ecFieldMulMod(state->curve, state->t2, state->t2, state->t6);
   //12. T6 = T1 - T4
   ecFieldSubMod(state->curve, state->t6, state->t1, state->t4);
   //13. T5 = T5 * T6
   ecFieldMulMod(state->curve, state->t5, state->t5, state->t6);
   //14. T5 = T5 - T2
   ecFieldSubMod(state->curve, state->t5, state->t5, state->t2);

   //R = (T4 : T5 : T3)
   ecScalarCopy(r->x, state->t4, pLen);
   ecScalarCopy(r->y, state->t5, pLen);
   ecScalarCopy(r->z, state->t3, pLen);

   //S = (T1 : T2 : T3)
   ecScalarCopy(s->x, state->t1, pLen);
   ecScalarCopy(s->y, state->t2, pLen);
   ecScalarCopy(s->z, state->t3, pLen);
}


/**
 * @brief Conjugate co-Z addition
 * @param[in] state Pointer to the working state
 * @param[out] r Output integer R
 * @param[out] s Output integer S
 * @param[in] p Output integer P
 * @param[in] q Output integer Q
 **/

void ecZaddc(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p,
   const EcPoint3 *q)
{
   uint_t pLen;

   //Get the length of the modulus, in words
   pLen = (state->curve->fieldSize + 31) / 32;

   //T1 = X1
   ecScalarCopy(state->t1, p->x, pLen);
   //T2 = Y1
   ecScalarCopy(state->t2, p->y, pLen);
   //T3 = Z
   ecScalarCopy(state->t3, p->z, pLen);
   //T4 = X2
   ecScalarCopy(state->t4, q->x, pLen);
   //T5 = Y2
   ecScalarCopy(state->t5, q->y, pLen);

   //1. T6 = T1 - T4
   ecFieldSubMod(state->curve, state->t6, state->t1, state->t4);
   //2. T3 = T3 * T6
   ecFieldMulMod(state->curve, state->t3, state->t3, state->t6);
   //3. T6 = T6 ^ 2
   ecFieldSqrMod(state->curve, state->t6, state->t6);
   //4. T7 = T1 * T6
   ecFieldMulMod(state->curve, state->t7, state->t1, state->t6);
   //5. T6 = T6 * T4
   ecFieldMulMod(state->curve, state->t6, state->t6, state->t4);
   //6. T1 = T2 + T5
   ecFieldAddMod(state->curve, state->t1, state->t2, state->t5);
   //7. T4 = T1 ^ 2
   ecFieldSqrMod(state->curve, state->t4, state->t1);
   //8. T4 = T4 - T7
   ecFieldSubMod(state->curve, state->t4, state->t4, state->t7);
   //9. T4 = T4 - T6
   ecFieldSubMod(state->curve, state->t4, state->t4, state->t6);
   //10. T1 = T2 - T5
   ecFieldSubMod(state->curve, state->t1, state->t2, state->t5);
   //11. T1 = T1 ^ 2
   ecFieldSqrMod(state->curve, state->t1, state->t1);
   //12. T1 = T1 - T7
   ecFieldSubMod(state->curve, state->t1, state->t1, state->t7);
   //13. T1 = T1 - T6
   ecFieldSubMod(state->curve, state->t1, state->t1, state->t6);
   //14. T6 = T6 - T7
   ecFieldSubMod(state->curve, state->t6, state->t6, state->t7);
   //15. T6 = T6 * T2
   ecFieldMulMod(state->curve, state->t6, state->t6, state->t2);
   //16. T2 = T2 - T5
   ecFieldSubMod(state->curve, state->t2, state->t2, state->t5);
   //17. T5 = 2 * T5
   ecFieldAddMod(state->curve, state->t5, state->t5, state->t5);
   //18. T5 = T2 + T5
   ecFieldAddMod(state->curve, state->t5, state->t2, state->t5);
   //19. T7 = T7 - T4
   ecFieldSubMod(state->curve, state->t7, state->t7, state->t4);
   //20. T5 = T5 * T7
   ecFieldMulMod(state->curve, state->t5, state->t5, state->t7);
   //21. T5 = T5 + T6
   ecFieldAddMod(state->curve, state->t5, state->t5, state->t6);
   //22. T7 = T4 + T7
   ecFieldAddMod(state->curve, state->t7, state->t4, state->t7);
   //23. T7 = T7 - T1
   ecFieldSubMod(state->curve, state->t7, state->t7, state->t1);
   //24. T2 = T2 * T7
   ecFieldMulMod(state->curve, state->t2, state->t2, state->t7);
   //25. T2 = T2 + T6
   ecFieldAddMod(state->curve, state->t2, state->t2, state->t6);

   //R = (T1 : T2 : T3)
   ecScalarCopy(r->x, state->t1, pLen);
   ecScalarCopy(r->y, state->t2, pLen);
   ecScalarCopy(r->z, state->t3, pLen);

   //S = (T4 : T5 : T3)
   ecScalarCopy(s->x, state->t4, pLen);
   ecScalarCopy(s->y, state->t5, pLen);
   ecScalarCopy(s->z, state->t3, pLen);
}


/**
 *@brief Co-Z doubling with update
 * @param[in] state Pointer to the working state
 * @param[out] r Output integer R
 * @param[out] s Output integer S
 * @param[in] p Output integer P
 **/

void ecDblu(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p)
{
   uint_t pLen;

   //Get the length of the modulus, in words
   pLen = (state->curve->fieldSize + 31) / 32;

   //T0 = a
   ecScalarCopy(state->t0, state->curve->a, pLen);
   //T1 = X1
   ecScalarCopy(state->t1, p->x, pLen);
   //T2 = Y1
   ecScalarCopy(state->t2, p->y, pLen);

   //1. T3 = 2 * T2
   ecFieldAddMod(state->curve, state->t3, state->t2, state->t2);
   //2. T2 = T2 ^ 2
   ecFieldSqrMod(state->curve, state->t2, state->t2);
   //3. T4 = T1 + T2
   ecFieldAddMod(state->curve, state->t4, state->t1, state->t2);
   //4. T4 = T4 ^ 2
   ecFieldSqrMod(state->curve, state->t4, state->t4);
   //5. T5 = T1 ^ 2
   ecFieldSqrMod(state->curve, state->t5, state->t1);
   //6. T4 = T4 - T5
   ecFieldSubMod(state->curve, state->t4, state->t4, state->t5);
   //7. T2 = T2 ^ 2
   ecFieldSqrMod(state->curve, state->t2, state->t2);
   //8. T4 = T4 - T2
   ecFieldSubMod(state->curve, state->t4, state->t4, state->t2);
   //9. T1 = 2 * T4
   ecFieldAddMod(state->curve, state->t1, state->t4, state->t4);
   //10. T0 = T0 + T5
   ecFieldAddMod(state->curve, state->t0, state->t0, state->t5);
   //11. T5 = 2 * T5
   ecFieldAddMod(state->curve, state->t5, state->t5, state->t5);
   //12. T0 = T0 + T5
   ecFieldAddMod(state->curve, state->t0, state->t0, state->t5);
   //13. T4 = T0 ^ 2
   ecFieldSqrMod(state->curve, state->t4, state->t0);
   //14. T5 = 2 * T1
   ecFieldAddMod(state->curve, state->t5, state->t1, state->t1);
   //15. T4 = T4 - T5
   ecFieldSubMod(state->curve, state->t4, state->t4, state->t5);
   //16. T2 = 8 * T2
   ecFieldAddMod(state->curve, state->t2, state->t2, state->t2);
   ecFieldAddMod(state->curve, state->t2, state->t2, state->t2);
   ecFieldAddMod(state->curve, state->t2, state->t2, state->t2);
   //17. T5 = T1 - T4
   ecFieldSubMod(state->curve, state->t5, state->t1, state->t4);
   //18. T5 = T5 * T0
   ecFieldMulMod(state->curve, state->t5, state->t5, state->t0);
   //19. T5 = T5 - T2
   ecFieldSubMod(state->curve, state->t5, state->t5, state->t2);

   //R = (T4 : T5 : T3)
   ecScalarCopy(r->x, state->t4, pLen);
   ecScalarCopy(r->y, state->t5, pLen);
   ecScalarCopy(r->z, state->t3, pLen);

   //S = (T1 : T2 : T3)
   ecScalarCopy(s->x, state->t1, pLen);
   ecScalarCopy(s->y, state->t2, pLen);
   ecScalarCopy(s->z, state->t3, pLen);
}


/**
 * @brief Co-Z tripling with update
 * @param[in] state Pointer to the working state
 * @param[out] r Output integer R
 * @param[out] s Output integer S
 * @param[in] p Output integer P
 **/

void ecTplu(EcState *state, EcPoint3 *r, EcPoint3 *s, const EcPoint3 *p)
{
   //(R, P) = DBLU(P)
   ecDblu(state, r, s, p);
   //(R, P) = ZADDU(P, R)
   ecZaddu(state, r, s, s, r);
}


/**
 * @brief Display the contents of an integer
 * @param[in] stream Pointer to a FILE object that identifies an output stream
 * @param[in] prepend String to prepend to the left of each line
 * @param[in] a Pointer to the integer to dump
 * @param[in] n Size of the integer, in words
 **/

void ecScalarDump(FILE *stream, const char_t *prepend, const uint32_t *a,
   uint_t n)
{
   uint_t i;

   //Process each word
   for(i = 0; i < n; i++)
   {
      //Beginning of a new line?
      if(i == 0 || ((n - i - 1) % 8) == 7)
      {
         fprintf(stream, "%s", prepend);
      }

      //Display current data
      fprintf(stream, "%08" PRIX32 " ", a[n - 1 - i]);

      //End of current line?
      if(((n - i - 1) % 8) == 0 || i == (n - 1))
      {
         fprintf(stream, "\r\n");
      }
   }
}

#endif
