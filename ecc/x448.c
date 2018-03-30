/**
 * @file x448.c
 * @brief X448 function implementation
 *
 * @section License
 *
 * Copyright (C) 2010-2018 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.8.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "ecc/ec_curves.h"
#include "ecc/curve448.h"
#include "ecc/x448.h"
#include "debug.h"

//Check crypto library configuration
#if (CURVE448_SUPPORT == ENABLED)


/**
 * @brief X448 function (scalar multiplication on Curve448)
 * @param[out] r Output u-coordinate
 * @param[in] k Input scalar
 * @param[in] u Input u-coordinate
 * @return Error code
 **/

error_t x448(uint8_t *r, const uint8_t *k, const uint8_t *u)
{
   int_t i;
   uint32_t b;
   uint32_t swap;
   X448Context *context;

   //Check parameters
   if(r == NULL || k == NULL || u == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allocate working context
   context = cryptoAllocMem(sizeof(X448Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy scalar
   curve448Import(context->k, k);

   //Set the two least significant bits of the first byte to 0, and the most
   //significant bit of the last byte to 1
   context->k[0] &= 0xFFFFFFFC;
   context->k[13] |= 0x80000000;

   //Copy input u-coordinate
   curve448Import(context->u, u);

   //Implementations must accept non-canonical values and process them as
   //if they had been reduced modulo the field prime (refer to RFC 7748,
   //section 5)
   curve448Red(context->u, context->u, 0);

   //Set X1 = 1
   curve448SetInt(context->x1, 1);
   //Set Z1 = 0
   curve448SetInt(context->z1, 0);
   //Set X2 = U
   curve448Copy(context->x2, context->u);
   //Set Z2 = 1
   curve448SetInt(context->z2, 1);

   //Set swap = 0
   swap = 0;

   //Montgomery ladder
   for(i = 447; i >= 0; i--)
   {
      //The scalar is processed in a left-to-right fashion
      b = (context->k[i / 32] >> (i % 32)) & 1;

      //Conditional swap
      curve448Swap(context->x1, context->x2, swap ^ b);
      curve448Swap(context->z1, context->z2, swap ^ b);

      //Save current bit value
      swap = b;

      //Compute T1 = X2 + Z2
      curve448Add(context->t1, context->x2, context->z2);
      //Compute X2 = X2 - Z2
      curve448Sub(context->x2, context->x2, context->z2);
      //Compute Z2 = X1 + Z1
      curve448Add(context->z2, context->x1, context->z1);
      //Compute X1 = X1 - Z1
      curve448Sub(context->x1, context->x1, context->z1);
      //Compute T1 = T1 * X1
      curve448Mul(context->t1, context->t1, context->x1);
      //Compute X2 = X2 * Z2
      curve448Mul(context->x2, context->x2, context->z2);
      //Compute Z2 = Z2 * Z2
      curve448Sqr(context->z2, context->z2);
      //Compute X1 = X1 * X1
      curve448Sqr(context->x1, context->x1);
      //Compute T2 = Z2 - X1
      curve448Sub(context->t2, context->z2, context->x1);
      //Compute Z1 = T2 * a24
      curve448MulInt(context->z1, context->t2, CURVE448_A24);
      //Compute Z1 = Z1 + X1
      curve448Add(context->z1, context->z1, context->x1);
      //Compute Z1 = Z1 * T2
      curve448Mul(context->z1, context->z1, context->t2);
      //Compute X1 = X1 * Z2
      curve448Mul(context->x1, context->x1, context->z2);
      //Compute Z2 = T1 - X2
      curve448Sub(context->z2, context->t1, context->x2);
      //Compute Z2 = Z2 * Z2
      curve448Sqr(context->z2, context->z2);
      //Compute Z2 = Z2 * U
      curve448Mul(context->z2, context->z2, context->u);
      //Compute X2 = X2 + T1
      curve448Add(context->x2, context->x2, context->t1);
      //Compute X2 = X2 * X2
      curve448Sqr(context->x2, context->x2);
   }

   //Conditional swap
   curve448Swap(context->x1, context->x2, swap);
   curve448Swap(context->z1, context->z2, swap);

   //Retrieve affine representation
   curve448Inv(context->u, context->z1);
   curve448Mul(context->u, context->u, context->x1);

   //Copy output u-coordinate
   curve448Export(context->u, r);

   //Erase working context
   cryptoMemset(context, 0, sizeof(X448Context));
   //Release previously allocated memory
   cryptoFreeMem(context);

   //Successful processing
   return NO_ERROR;
}

#endif
