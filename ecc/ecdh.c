/**
 * @file ecdh.c
 * @brief ECDH (Elliptic Curve Diffie-Hellman) key exchange
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
#include "ecc/ecdh.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (ECDH_SUPPORT == ENABLED)


/**
 * @brief Initialize ECDH context
 * @param[in] context Pointer to the ECDH context
 **/

void ecdhInit(EcdhContext *context)
{
   //Initialize elliptic curve parameters
   context->curve = NULL;

   //Initialize private and public keys
   ecInitPrivateKey(&context->da);
   ecInitPublicKey(&context->qb);
}


/**
 * @brief Release ECDH context
 * @param[in] context Pointer to the ECDH context
 **/

void ecdhFree(EcdhContext *context)
{
   //Release elliptic curve parameters
   context->curve = NULL;

   //Release private and public keys
   ecFreePrivateKey(&context->da);
   ecFreePublicKey(&context->qb);
}


/**
 * @brief Specify the elliptic curve to use
 * @param[in] context Pointer to the ECDH context
 * @param[in] curve Elliptic curve parameters
 * @return Error code
 **/

error_t ecdhSetCurve(EcdhContext *context, const EcCurve *curve)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(context != NULL && curve != NULL)
   {
      //Save elliptic curve parameters
      context->curve = curve;
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
 * @brief ECDH key pair generation
 * @param[in] context Pointer to the ECDH context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t ecdhGenerateKeyPair(EcdhContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   error_t error;

   //Debug message
   TRACE_DEBUG("Generating ECDH key pair...\r\n");

   //Weierstrass elliptic curve?
   if(context->curve->type == EC_CURVE_TYPE_WEIERSTRASS ||
      context->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0 ||
      context->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
   {
      //Generate an EC key pair
      error = ecGenerateKeyPair(prngAlgo, prngContext, context->curve,
         &context->da, NULL);
   }
#if (X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   else if(context->curve->type == EC_CURVE_TYPE_MONTGOMERY &&
      context->curve->fieldSize == CURVE25519_BIT_LEN)
   {
      uint8_t da[CURVE25519_BYTE_LEN];
      uint8_t qa[CURVE25519_BYTE_LEN];
      uint8_t g[CURVE25519_BYTE_LEN];

      //Generate 32 random bytes
      error = prngAlgo->generate(prngContext, da, CURVE25519_BYTE_LEN);

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Private key:\r\n");
         TRACE_DEBUG_ARRAY("    ", da, CURVE25519_BYTE_LEN);

         //Get the u-coordinate of the base point
         error = ecScalarExport(context->curve->g.x, CURVE25519_WORD_LEN, g,
            CURVE25519_BYTE_LEN, EC_SCALAR_FORMAT_LITTLE_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Generate the public value using X25519 function
         error = x25519(qa, da, g);
      }

      //Check status code
      if(!error)
      {
         //Save private key
         error = ecImportPrivateKey(&context->da, X25519_CURVE, da,
            CURVE25519_BYTE_LEN);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Public key:\r\n");
         TRACE_DEBUG_ARRAY("    ", qa, CURVE25519_BYTE_LEN);

         //Save public key
         error = ecImportPublicKey(&context->da.q, X25519_CURVE, qa,
            CURVE25519_BYTE_LEN, EC_PUBLIC_KEY_FORMAT_RAW);
      }
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   else if(context->curve->type == EC_CURVE_TYPE_MONTGOMERY &&
      context->curve->fieldSize == CURVE448_BIT_LEN)
   {
      uint8_t da[CURVE448_BYTE_LEN];
      uint8_t qa[CURVE448_BYTE_LEN];
      uint8_t g[CURVE448_BYTE_LEN];

      //Generate 56 random bytes
      error = prngAlgo->generate(prngContext, da, CURVE448_BYTE_LEN);

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Private key:\r\n");
         TRACE_DEBUG_ARRAY("    ", da, CURVE448_BYTE_LEN);

         //Get the u-coordinate of the base point
         error = ecScalarExport(context->curve->g.x, CURVE448_WORD_LEN, g,
            CURVE448_BYTE_LEN, EC_SCALAR_FORMAT_LITTLE_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Generate the public value using X448 function
         error = x448(qa, da, g);
      }

      //Check status code
      if(!error)
      {
         //Save private key
         error = ecImportPrivateKey(&context->da, X448_CURVE, da,
            CURVE448_BYTE_LEN);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("  Public key:\r\n");
         TRACE_DEBUG_ARRAY("    ", qa, CURVE448_BYTE_LEN);

         //Save public key
         error = ecImportPublicKey(&context->da.q, X448_CURVE, qa,
            CURVE448_BYTE_LEN, EC_PUBLIC_KEY_FORMAT_RAW);
      }
   }
#endif
   //Invalid elliptic curve?
   else
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
}


/**
 * @brief Export our own public key
 * @param[in] context Pointer to the ECDH context
 * @param[out] output Pointer to the octet string
 * @param[out] written Length of the octet string, in bytes
 * @param[in] format EC public key format (X9.63 or raw format)
 * @return Error code
 **/

error_t ecdhExportPublicKey(EcdhContext *context, uint8_t *output,
   size_t *written, EcPublicKeyFormat format)
{
   //Export our own public key
   return ecExportPublicKey(&context->da.q, output, written, format);
}


/**
 * @brief Import peer's public key
 * @param[in] context Pointer to the ECDH context
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @param[in] format EC public key format (X9.63 or raw format)
 * @return Error code
 **/

error_t ecdhImportPeerPublicKey(EcdhContext *context, const uint8_t *input,
   size_t length, EcPublicKeyFormat format)
{
   error_t error;

   //Import peer's public key
   error = ecImportPublicKey(&context->qb, context->curve, input, length, format);

   //Check status code
   if(!error)
   {
      //Ensure the public key is acceptable
      error = ecdhCheckPublicKey(context, &context->qb);
   }

   //Return status code
   return error;
}


/**
 * @brief Check public key
 * @param[in] context Pointer to the ECDH context
 * @param[in] publicKey Public key to be checked
 * @return Error code
 **/

error_t ecdhCheckPublicKey(EcdhContext *context, const EcPublicKey *publicKey)
{
   bool_t valid;

   //Weierstrass elliptic curve?
   if(context->curve->type == EC_CURVE_TYPE_WEIERSTRASS ||
      context->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0 ||
      context->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
   {
      //Initialize flag
      valid = TRUE;

      //Verify that the curve is valid
      if(publicKey->curve != context->curve)
      {
         valid = FALSE;
      }

      //Verify that 0 <= Qx < p
      if(valid)
      {
         if(ecScalarComp(publicKey->q.x, context->curve->p,
            EC_MAX_MODULUS_SIZE) >= 0)
         {
            valid = FALSE;
         }
      }

      //Verify that 0 <= Qy < p
      if(valid)
      {
         if(ecScalarComp(publicKey->q.y, context->curve->p,
            EC_MAX_MODULUS_SIZE) >= 0)
         {
            valid = FALSE;
         }
      }

      //Check whether the point is on the curve
      if(valid)
      {
         valid = ecIsPointAffine(context->curve, &publicKey->q);
      }

      //If the cofactor is not 1, the implementation must verify that n.Q is
      //the point at the infinity
      if(valid)
      {
         if(context->curve->h != 1)
         {
            error_t error;
            uint_t pLen;
            EcPoint3 r;

            //Initialize flag
            valid = FALSE;

            //Get the length of the modulus, in words
            pLen = (context->curve->fieldSize + 31) / 32;

            //Convert the public key to projective representation
            ecProjectify(context->curve, &r, &publicKey->q);

            //Compute R = n.Q
            error = ecMulFast(context->curve, &r, context->curve->q, &r);

            //Check status code
            if(!error)
            {
               //Verify that the result is the point at the infinity
               if(ecScalarCompInt(r.z, 0, pLen) == 0)
               {
                  valid = TRUE;
               }
            }
         }
      }
   }
#if (X25519_SUPPORT == ENABLED || X448_SUPPORT == ENABLED)
   //Curve25519 or Curve448 elliptic curve?
   else if(context->curve->type == EC_CURVE_TYPE_MONTGOMERY)
   {
      //The public key does not need to be validated
      valid = TRUE;
   }
#endif
   //Invalid elliptic curve?
   else
   {
      //Just for sanity
      valid = FALSE;
   }

   //Return status code
   if(valid)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_ILLEGAL_PARAMETER;
   }
}


/**
 * @brief Compute ECDH shared secret
 * @param[in] context Pointer to the ECDH context
 * @param[out] output Buffer where to store the shared secret
 * @param[in] outputSize Size of the buffer in bytes
 * @param[out] outputLen Length of the resulting shared secret
 * @return Error code
 **/

error_t ecdhComputeSharedSecret(EcdhContext *context, uint8_t *output,
   size_t outputSize, size_t *outputLen)
{
   error_t error;

   //Debug message
   TRACE_DEBUG("Computing Diffie-Hellman shared secret...\r\n");

   //Weierstrass elliptic curve?
   if(context->curve->type == EC_CURVE_TYPE_WEIERSTRASS ||
      context->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0 ||
      context->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
   {
      size_t k;
      EcPoint3 q;
      EcPoint3 z;

      //Get the length in octets of the prime modulus
      k = (context->curve->fieldSize + 7) / 8;

      //Make sure that the output buffer is large enough
      if(outputSize >= k)
      {
         //Length of the resulting shared secret
         *outputLen = k;

         //Convert the peer's public key to projective representation
         ecProjectify(context->curve, &q, &context->qb.q);

         //Compute Z = da.Qb
         error = ecMulRegular(context->curve, &z, context->da.d, &q);

         //Check status code
         if(!error)
         {
            //Convert Z to affine representation
            error = ecAffinify(context->curve, &z, &z);
         }

         //Check status code
         if(!error)
         {
            //The shared secret is the x-coordinate of Z
            error = ecScalarExport(z.x, (k + 3) / 4, output, k,
               EC_SCALAR_FORMAT_BIG_ENDIAN);
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
#if (X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   else if(context->curve->type == EC_CURVE_TYPE_MONTGOMERY &&
      context->curve->fieldSize == CURVE25519_BIT_LEN)
   {
      uint_t i;
      uint8_t mask;
      uint8_t da[CURVE25519_BYTE_LEN];
      uint8_t qb[CURVE25519_BYTE_LEN];

      //Make sure that the output buffer is large enough
      if(outputSize >= CURVE25519_BYTE_LEN)
      {
         //Length of the resulting shared secret
         *outputLen = CURVE25519_BYTE_LEN;

         //Get private key
         error = ecScalarExport(context->da.d, CURVE25519_WORD_LEN, da,
            CURVE25519_BYTE_LEN, EC_SCALAR_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Get peer's public key
            error = ecScalarExport(context->qb.q.x, CURVE25519_WORD_LEN, qb,
               CURVE25519_BYTE_LEN, EC_SCALAR_FORMAT_LITTLE_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Generate shared secret K using X25519 function
            error = x25519(output, da, qb);
         }

         //Since Curve25519 has a cofactor of 8, an input point of small order
         //will eliminate any contribution from the other party's private key
         if(!error)
         {
            //This situation can be detected by checking for the all-zero output
            for(mask = 0, i = 0; i < CURVE25519_BYTE_LEN; i++)
            {
               mask |= output[i];
            }

            //Check whether K is the all-zero value and abort if so (refer to
            //RFC 8422, sections 5.10 and 5.11)
            if(mask == 0)
            {
               error = ERROR_ILLEGAL_PARAMETER;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   else if(context->curve->type == EC_CURVE_TYPE_MONTGOMERY &&
      context->curve->fieldSize == CURVE448_BIT_LEN)
   {
      uint_t i;
      uint8_t mask;
      uint8_t da[CURVE448_BYTE_LEN];
      uint8_t qb[CURVE448_BYTE_LEN];

      //Make sure that the output buffer is large enough
      if(outputSize >= CURVE448_BYTE_LEN)
      {
         //Length of the resulting shared secret
         *outputLen = CURVE448_BYTE_LEN;

         //Get private key
         error = ecScalarExport(context->da.d, CURVE448_WORD_LEN, da,
            CURVE448_BYTE_LEN, EC_SCALAR_FORMAT_LITTLE_ENDIAN);

         //Check status code
         if(!error)
         {
            //Get peer's public key
            error = ecScalarExport(context->qb.q.x, CURVE448_WORD_LEN, qb,
               CURVE448_BYTE_LEN, EC_SCALAR_FORMAT_LITTLE_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Generate shared secret K using X448 function
            error = x448(output, da, qb);
         }

         //Since Curve448 has a cofactor of 4, an input point of small order
         //will eliminate any contribution from the other party's private key
         if(!error)
         {
            //This situation can be detected by checking for the all-zero output
            for(mask = 0, i = 0; i < CURVE448_BYTE_LEN; i++)
            {
               mask |= output[i];
            }

            //Check whether K is the all-zero value and abort if so (refer to
            //RFC 8422, sections 5.10 and 5.11)
            if(mask == 0)
            {
               error = ERROR_ILLEGAL_PARAMETER;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }
#endif
   //Invalid elliptic curve?
   else
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  Shared secret (%" PRIuSIZE " bytes):\r\n", *outputLen);
      TRACE_DEBUG_ARRAY("    ", output, *outputLen);
   }

   //Return status code
   return error;
}

#endif
