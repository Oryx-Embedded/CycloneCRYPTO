/**
 * @file ecdh.c
 * @brief ECDH (Elliptic Curve Diffie-Hellman) key exchange
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
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
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "ecc/ecdh.h"
#include "debug.h"

//Check crypto library configuration
#if (ECDH_SUPPORT == ENABLED)


/**
 * @brief Initialize ECDH context
 * @param[in] context Pointer to the ECDH context
 **/

void ecdhInit(EcdhContext *context)
{
   //Initialize EC domain parameters
   ecInitDomainParameters(&context->params);
   //Initialize private and public keys
   mpiInit(&context->da);
   ecInit(&context->qa);
   ecInit(&context->qb);
}


/**
 * @brief Release ECDH context
 * @param[in] context Pointer to the ECDH context
 **/

void ecdhFree(EcdhContext *context)
{
   //Release EC domain parameters
   ecFreeDomainParameters(&context->params);
   //Release private and public keys
   mpiFree(&context->da);
   ecFree(&context->qa);
   ecFree(&context->qb);
}


/**
 * @brief ECDH key pair generation
 * @param[in] context Pointer to the ECDH context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t ecdhGenerateKeyPair(EcdhContext *context,
   const PrngAlgo *prngAlgo, void *prngContext)
{
   error_t error;
   uint_t n;

   //Debug message
   TRACE_DEBUG("Generating ECDH key pair...\r\n");

   //Let N be the bit length of q
   n = mpiGetBitLength(&context->params.q);

   //Generated a pseudorandom number
   MPI_CHECK(mpiRand(&context->da, n, prngAlgo, prngContext));

   //Make sure that 0 < da < q
   if(mpiComp(&context->da, &context->params.q) >= 0)
      mpiShiftRight(&context->da, 1);

   //Debug message
   TRACE_DEBUG("  Private key:\r\n");
   TRACE_DEBUG_MPI("    ", &context->da);

   //Compute Qa = da.G
   EC_CHECK(ecMult(&context->params, &context->qa, &context->da, &context->params.g));
   EC_CHECK(ecAffinify(&context->params, &context->qa, &context->qa));

   //Debug message
   TRACE_DEBUG("  Public key X:\r\n");
   TRACE_DEBUG_MPI("    ", &context->qa.x);
   TRACE_DEBUG("  Public key Y:\r\n");
   TRACE_DEBUG_MPI("    ", &context->qa.y);

end:
   //Return status code
   return error;
}


/**
 * @brief Check ECDH public key
 * @param[in] params EC domain parameters
 * @param[in] publicKey Public key to be checked
 * @return Error code
 **/

error_t ecdhCheckPublicKey(const EcDomainParameters *params, EcPoint *publicKey)
{
   bool_t valid;

   //Verify that 0 <= Qx < p
   if(mpiCompInt(&publicKey->x, 0) < 0)
      return ERROR_ILLEGAL_PARAMETER;
   else if(mpiComp(&publicKey->x, &params->p) >= 0)
      return ERROR_ILLEGAL_PARAMETER;

   //Verify that 0 <= Qy < p
   if(mpiCompInt(&publicKey->y, 0) < 0)
      return ERROR_ILLEGAL_PARAMETER;
   else if(mpiComp(&publicKey->y, &params->p) >= 0)
      return ERROR_ILLEGAL_PARAMETER;

   //Check whether the point is on the curve
   valid = ecIsPointAffine(params, publicKey);

   //Return status code
   if(valid)
      return NO_ERROR;
   else
      return ERROR_ILLEGAL_PARAMETER;
}


/**
 * @brief Compute ECDH shared secret
 * @param[in] context Pointer to the ECDH context
 * @param[out] output Buffer where to store the shared secret
 * @param[in] outputSize Size of the buffer in bytes
 * @param[out] outputLen Length of the resulting shared secret
 * @return Error code
 **/

error_t ecdhComputeSharedSecret(EcdhContext *context,
   uint8_t *output, size_t outputSize, size_t *outputLen)
{
   error_t error;
   size_t k;
   EcPoint z;

   //Debug message
   TRACE_DEBUG("Computing Diffie-Hellman shared secret...\r\n");

   //Get the length in octets of the prime modulus
   k = mpiGetByteLength(&context->params.p);

   //Make sure that the output buffer is large enough
   if(outputSize < k)
      return ERROR_INVALID_LENGTH;

   //Initialize EC points
   ecInit(&z);

   //Compute Z = da.Qb
   EC_CHECK(ecProjectify(&context->params, &context->qb, &context->qb));
   EC_CHECK(ecMult(&context->params, &z, &context->da, &context->qb));
   EC_CHECK(ecAffinify(&context->params, &z, &z));

   //Convert the x-coordinate of Z to an octet string
   MPI_CHECK(mpiWriteRaw(&z.x, output, k));

   //Length of the resulting shared secret
   *outputLen = k;

   //Debug message
   TRACE_DEBUG("  Shared secret (%" PRIuSIZE " bytes):\r\n", *outputLen);
   TRACE_DEBUG_ARRAY("    ", output, *outputLen);

end:
   //Release EC points
   ecFree(&z);

   //Return status code
   return error;
}

#endif
