/**
 * @file sm2.c
 * @brief SM2 signature algorithm
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
 * @version 2.4.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/hash_algorithms.h"
#include "ecc/sm2.h"
#include "debug.h"

//Check crypto library configuration
#if (SM2_SUPPORT == ENABLED)

//SM2 with SM3 OID (1.2.156.10197.1.501)
const uint8_t SM2_WITH_SM3_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75};


/**
 * @brief SM2 signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[in] privateKey Signer's EC private key
 * @param[in] hashAlgo Underlying hash function
 * @param[in] id User's identity
 * @param[in] idLen Length of the user's identity
 * @param[in] message Message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] signature (r, s) integer pair
 * @return Error code
 **/

error_t sm2GenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, const EcPrivateKey *privateKey,
   const HashAlgo *hashAlgo, const char_t *id, size_t idLen,
   const void *message, size_t messageLen, EcdsaSignature *signature)
{
   error_t error;
   Mpi e;
   Mpi k;
   Mpi t;
   EcPoint p1;
   EcPublicKey pa;
   uint8_t buffer[32];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //Check parameters
   if(params == NULL || privateKey == NULL || hashAlgo == NULL || id == NULL ||
      message == NULL || signature == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Sanity check
   if(hashAlgo->digestSize > sizeof(buffer))
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("SM2 signature generation...\r\n");
   TRACE_DEBUG("  private key:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->d);
   TRACE_DEBUG("  identifier:\r\n");
   TRACE_DEBUG_ARRAY("    ", id, idLen);
   TRACE_DEBUG("  message:\r\n");
   TRACE_DEBUG_ARRAY("    ", message, messageLen);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hashAlgo->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize multiple precision integers
   mpiInit(&e);
   mpiInit(&k);
   mpiInit(&t);
   //Initialize EC points
   ecInit(&p1);
   //Initialize EC public key
   ecInitPublicKey(&pa);

   //Derive the public key from the signer's EC private key
   EC_CHECK(ecGeneratePublicKey(params, privateKey, &pa));

   //Calculate ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
   EC_CHECK(sm2ComputeZa(hashAlgo, hashContext, params, &pa, id, idLen,
      buffer));

   //Let M~ = ZA || M and calculate Hv(M~)
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, buffer, hashAlgo->digestSize);
   hashAlgo->update(hashContext, message, messageLen);
   hashAlgo->final(hashContext, buffer);

   //Let e = Hv(M~)
   MPI_CHECK(mpiImport(&e, buffer, hashAlgo->digestSize,
      MPI_FORMAT_BIG_ENDIAN));

   //SM2 signature generation process
   do
   {
      do
      {
         //Pick a random number k in [1, q-1]
         MPI_CHECK(mpiRandRange(&k, &params->q, prngAlgo, prngContext));

         //Debug message
         TRACE_DEBUG("  k:\r\n");
         TRACE_DEBUG_MPI("    ", &k);

         //Calculate the elliptic curve point (x1, y1) = [k]G
         EC_CHECK(ecMult(params, &p1, &k, &params->g));
         EC_CHECK(ecAffinify(params, &p1, &p1));

         //Calculate r = (e + x1) mod q
         MPI_CHECK(mpiAddMod(&signature->r, &e, &p1.x, &params->q));

         //Calculate r + k
         MPI_CHECK(mpiAdd(&t, &signature->r, &k));

         //If r = 0 or r + k = n, then generate a new random number
      } while(mpiCompInt(&signature->r, 0) == 0 || mpiComp(&t, &params->q) == 0);

      //Calculate s = ((1 + dA)^-1 * (k - r * dA)) mod q
      MPI_CHECK(mpiAddInt(&t, &privateKey->d, 1));
      MPI_CHECK(mpiInvMod(&signature->s, &t, &params->q));
      MPI_CHECK(mpiMulMod(&t, &signature->r, &privateKey->d, &params->q));
      MPI_CHECK(mpiSubMod(&t, &k, &t, &params->q));
      MPI_CHECK(mpiMulMod(&signature->s, &signature->s, &t, &params->q));

      //If s = 0, then generate a new random number
   } while(mpiCompInt(&signature->s, 0) == 0);

   //Debug message
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

end:
   //Release multiple precision integers
   mpiFree(&e);
   mpiFree(&k);
   mpiFree(&t);
   //Release EC points
   ecFree(&p1);
   //Release EC public key
   ecFreePublicKey(&pa);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(hashContext);
#endif

   //Clean up side effects if necessary
   if(error)
   {
      //Release (r, r) integer pair
      mpiFree(&signature->r);
      mpiFree(&signature->s);
   }

   //Return status code
   return error;
}


/**
 * @brief SM2 signature verification
 * @param[in] params EC domain parameters
 * @param[in] publicKey Signer's SM2 public key
 * @param[in] hashAlgo Underlying hash function
 * @param[in] id User's identity
 * @param[in] idLen Length of the user's identity
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signature (r, s) integer pair
 * @return Error code
 **/

error_t sm2VerifySignature(const EcDomainParameters *params,
   const EcPublicKey *publicKey, const HashAlgo *hashAlgo,
   const char_t *id, size_t idLen, const void *message, size_t messageLen,
   const EcdsaSignature *signature)
{
   error_t error;
   Mpi e;
   Mpi t;
   Mpi r;
   EcPoint pa;
   EcPoint p1;
   uint8_t buffer[32];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //Check parameters
   if(params == NULL || publicKey == NULL || hashAlgo == NULL || id == NULL ||
      message == NULL || signature == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Sanity check
   if(hashAlgo->digestSize > sizeof(buffer))
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("SM2 signature verification...\r\n");
   TRACE_DEBUG("  public key X:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.x);
   TRACE_DEBUG("  public key Y:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.y);
   TRACE_DEBUG("  identifier:\r\n");
   TRACE_DEBUG_ARRAY("    ", id, idLen);
   TRACE_DEBUG("  message:\r\n");
   TRACE_DEBUG_ARRAY("    ", message, messageLen);
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

   //The verifier shall check that 0 < r < q
   if(mpiCompInt(&signature->r, 0) <= 0 ||
      mpiComp(&signature->r, &params->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(mpiCompInt(&signature->s, 0) <= 0 ||
      mpiComp(&signature->s, &params->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hashAlgo->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize multiple precision integers
   mpiInit(&e);
   mpiInit(&t);
   mpiInit(&r);
   //Initialize EC points
   ecInit(&pa);
   ecInit(&p1);

   //Calculate ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
   EC_CHECK(sm2ComputeZa(hashAlgo, hashContext, params, publicKey, id, idLen,
      buffer));

   //Let M~ = ZA || M and calculate Hv(M~)
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, buffer, hashAlgo->digestSize);
   hashAlgo->update(hashContext, message, messageLen);
   hashAlgo->final(hashContext, buffer);

   //Let e = Hv(M~)
   MPI_CHECK(mpiImport(&e, buffer, hashAlgo->digestSize,
      MPI_FORMAT_BIG_ENDIAN));

   //Calculate t = (r + s) mod q
   MPI_CHECK(mpiAddMod(&t, &signature->r, &signature->s, &params->q));

   //Test if t = 0
   if(mpiCompInt(&t, 0) == 0)
   {
      //Verification failed
      error = ERROR_INVALID_SIGNATURE;
   }
   else
   {
      //Calculate the point (x1, y1)=[s]G + [t]PA
      EC_CHECK(ecProjectify(params, &pa, &publicKey->q));
      EC_CHECK(ecTwinMult(params, &p1, &signature->s, &params->g, &t, &pa));
      EC_CHECK(ecAffinify(params, &p1, &p1));

      //Calculate R = (e + x1) mod q
      MPI_CHECK(mpiAddMod(&r, &e, &p1.x, &params->q));

      //Verify that R = r
      if(mpiComp(&r, &signature->r) == 0)
      {
         //Verification succeeded
         error = NO_ERROR;
      }
      else
      {
         //Verification failed
         error = ERROR_INVALID_SIGNATURE;
      }
   }

end:
   //Release multiple precision integers
   mpiFree(&e);
   mpiFree(&t);
   mpiFree(&r);
   //Release EC points
   ecFree(&pa);
   ecFree(&p1);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(hashContext);
#endif

   //Return status code
   return error;
}


/**
 * @brief Calculate ZA
 * @param[in] hashAlgo Hash function
 * @param[in] hashContext Hash function context
 * @param[in] params EC domain parameters
 * @param[in] pa Public key of user A
 * @param[in] ida Distinguishing identifier of user A
 * @param[in] idaLen Length of the identifier
 * @param[out] za Hash value of the distinguishing identifier of user A
 **/

error_t sm2ComputeZa(const HashAlgo *hashAlgo, HashContext *hashContext,
   const EcDomainParameters *params, const EcPublicKey *pa, const char_t *ida,
   size_t idaLen, uint8_t *za)
{
   error_t error;
   size_t n;
   uint8_t buffer[32];

   //Get the length in octets of the prime modulus
   n = mpiGetByteLength(&params->p);

   //Sanity check
   if(n > sizeof(buffer))
      return ERROR_INVALID_PARAMETER;

   //Format ENTLA
   STORE16BE(idaLen * 8, buffer);

   //Calculate ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
   hashAlgo->init(hashContext);

   //Digest ENTLA || IDA
   hashAlgo->update(hashContext, buffer, sizeof(uint16_t));
   hashAlgo->update(hashContext, ida, idaLen);

   //Convert the parameter a to bit string
   error = mpiExport(&params->a, buffer, n, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the parameter a
   hashAlgo->update(hashContext, buffer, n);

   //Convert the parameter b to bit string
   error = mpiExport(&params->b, buffer, n, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the parameter b
   hashAlgo->update(hashContext, buffer, n);

   //Convert the coordinate xG to bit string
   error = mpiExport(&params->g.x, buffer, n, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the coordinate xG
   hashAlgo->update(hashContext, buffer, n);

   //Convert the coordinate yG to bit string
   error = mpiExport(&params->g.y, buffer, n, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the coordinate yG
   hashAlgo->update(hashContext, buffer, n);

   //Convert the public key's coordinate xA to bit string
   error = mpiExport(&pa->q.x, buffer, n, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the public key's coordinate xA
   hashAlgo->update(hashContext, buffer, n);

   //Convert the public key's coordinate yA to bit string
   error = mpiExport(&pa->q.y, buffer, n, MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the public key's coordinate yA
   hashAlgo->update(hashContext, buffer, n);

   //Finalize ZA calculation
   hashAlgo->final(hashContext, za);

   //Debug message
   TRACE_DEBUG("  ZA:\r\n");
   TRACE_DEBUG_ARRAY("    ", za, hashAlgo->digestSize);

   //Return status code
   return error;
}

#endif
