/**
 * @file sm2.c
 * @brief SM2 signature algorithm
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
#include "hash/hash_algorithms.h"
#include "ecc/sm2.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (SM2_SUPPORT == ENABLED)

//SM2 with SM3 OID (1.2.156.10197.1.501)
const uint8_t SM2_WITH_SM3_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75};


/**
 * @brief SM2 signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
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
   const EcPrivateKey *privateKey, const HashAlgo *hashAlgo, const char_t *id,
   size_t idLen, const void *message, size_t messageLen,
   EcdsaSignature *signature)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Sm2GenerateSignatureState *state;
#else
   Sm2GenerateSignatureState state[1];
#endif

   //Check parameters
   if(privateKey == NULL || hashAlgo == NULL || id == NULL ||
      message == NULL || signature == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid elliptic curve?
   if(privateKey->curve == NULL ||
      privateKey->curve->fieldSize != 256 ||
      privateKey->curve->orderSize != 256)
   {
      return ERROR_INVALID_ELLIPTIC_CURVE;
   }

   //Invalid hash algorithm?
   if(hashAlgo->digestSize != 32)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("SM2 signature generation...\r\n");
   TRACE_DEBUG("  private key:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", privateKey->d, 8);
   TRACE_DEBUG("  identifier:\r\n");
   TRACE_DEBUG_ARRAY("    ", id, idLen);
   TRACE_DEBUG("  message:\r\n");
   TRACE_DEBUG_ARRAY("    ", message, messageLen);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(Sm2GenerateSignatureState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(Sm2GenerateSignatureState));

   //Initialize (R, S) integer pair
   ecScalarSetInt(signature->r, 0, EC_MAX_ORDER_SIZE);
   ecScalarSetInt(signature->s, 0, EC_MAX_ORDER_SIZE);

   //Initialize status code
   error = NO_ERROR;

   //Valid public key?
   if(privateKey->q.curve != NULL)
   {
      //Let PA be the public key
      ecProjectify(privateKey->curve, &state->pa, &privateKey->q.q);
   }
   else
   {
      //Derive the public key from the signer's EC private key
      error = ecMulRegular(privateKey->curve, &state->pa, privateKey->d,
         &privateKey->curve->g);

      //Check status code
      if(!error)
      {
         //Convert PA to affine representation
         error = ecAffinify(privateKey->curve, &state->pa, &state->pa);
      }
   }

   //Check status code
   if(!error)
   {
      //Calculate ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
      error = sm2ComputeZa(hashAlgo, &state->hashContext, privateKey->curve,
         &state->pa, id, idLen, state->buffer);
   }

   //Check status code
   if(!error)
   {
      //Let M~ = ZA || M and calculate Hv(M~)
      hashAlgo->init(&state->hashContext);
      hashAlgo->update(&state->hashContext, state->buffer, hashAlgo->digestSize);
      hashAlgo->update(&state->hashContext, message, messageLen);
      hashAlgo->final(&state->hashContext, state->buffer);

      //Let e = Hv(M~)
      error = ecScalarImport(state->e, 8, state->buffer, hashAlgo->digestSize,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Initialize status code
      error = ERROR_INVALID_VALUE;

      //SM2 signature generation process
      while(error == ERROR_INVALID_VALUE)
      {
         //Inner loop
         while(error == ERROR_INVALID_VALUE)
         {
            //Pick a random number k in range 0 < k < q - 1
            error = ecScalarRand(privateKey->curve, state->k, prngAlgo,
               prngContext);

            //Check status code
            if(!error)
            {
               //Debug message
               TRACE_DEBUG("  k:\r\n");
               TRACE_DEBUG_EC_SCALAR("    ", state->k, 8);

               //Calculate the elliptic curve point (x1, y1) = [k]G
               error = ecMulRegular(privateKey->curve, &state->p1, state->k,
                  &privateKey->curve->g);
            }

            //Check status code
            if(!error)
            {
               //Convert P1 to affine representation
               error = ecAffinify(privateKey->curve, &state->p1, &state->p1);
            }

            //Check status code
            if(!error)
            {
               //Calculate r = (e + x1) mod q
               ecScalarMod(signature->r, state->p1.x, 8, privateKey->curve->q, 8);
               ecScalarAddMod(privateKey->curve, signature->r, signature->r, state->e);

               //Calculate r + k
               ecScalarAdd(state->t, signature->r, state->k, 8);

               //If r = 0 or r + k = n, then generate a new random number
               if(ecScalarCompInt(signature->r, 0, 8) == 0 ||
                  ecScalarComp(state->t, privateKey->curve->q, 8) == 0)
               {
                  error = ERROR_INVALID_VALUE;
               }
            }
         }

         //Check status code
         if(!error)
         {
            //Calculate s = ((1 + dA)^-1 * (k - r * dA)) mod q
            ecScalarSetInt(state->t, 1, 8);
            ecScalarAddMod(privateKey->curve, state->t, state->t, privateKey->d);
            ecScalarInvMod(privateKey->curve, signature->s, state->t);
            ecScalarMulMod(privateKey->curve, state->t, signature->r, privateKey->d);
            ecScalarSubMod(privateKey->curve, state->t, state->k, state->t);
            ecScalarMulMod(privateKey->curve, signature->s, signature->s, state->t);

            //If s = 0, then generate a new random number
            if(ecScalarCompInt(signature->s, 0, 8) == 0)
            {
               error = ERROR_INVALID_VALUE;
            }
         }
      }
   }

   //Check status code
   if(!error)
   {
      //Save elliptic curve parameters
      signature->curve = privateKey->curve;

      //Debug message
      TRACE_DEBUG("  r:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", signature->r, 8);
      TRACE_DEBUG("  s:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", signature->s, 8);
   }

   //Erase working state
   osMemset(state, 0, sizeof(Sm2GenerateSignatureState));

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release working state
   cryptoFreeMem(state);
#endif

   //Return status code
   return error;
}


/**
 * @brief SM2 signature verification
 * @param[in] publicKey Signer's SM2 public key
 * @param[in] hashAlgo Underlying hash function
 * @param[in] id User's identity
 * @param[in] idLen Length of the user's identity
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signature (r, s) integer pair
 * @return Error code
 **/

error_t sm2VerifySignature(const EcPublicKey *publicKey,
   const HashAlgo *hashAlgo, const char_t *id, size_t idLen,
   const void *message, size_t messageLen, const EcdsaSignature *signature)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Sm2VerifySignatureState *state;
#else
   Sm2VerifySignatureState state[1];
#endif

   //Check parameters
   if(publicKey == NULL || hashAlgo == NULL || id == NULL || message == NULL ||
      signature == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid elliptic curve?
   if(publicKey->curve == NULL ||
      publicKey->curve->fieldSize != 256 ||
      publicKey->curve->orderSize != 256)
   {
      return ERROR_INVALID_ELLIPTIC_CURVE;
   }

   //Invalid hash algorithm?
   if(hashAlgo->digestSize != 32)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("SM2 signature verification...\r\n");
   TRACE_DEBUG("  public key X:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", publicKey->q.x, 8);
   TRACE_DEBUG("  public key Y:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", publicKey->q.y, 8);
   TRACE_DEBUG("  identifier:\r\n");
   TRACE_DEBUG_ARRAY("    ", id, idLen);
   TRACE_DEBUG("  message:\r\n");
   TRACE_DEBUG_ARRAY("    ", message, messageLen);
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", signature->r, 8);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", signature->s, 8);

   //Verify that the public key is on the curve
   if(!ecIsPointAffine(publicKey->curve, &publicKey->q))
   {
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < r < q
   if(ecScalarCompInt(signature->r, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->r, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(ecScalarCompInt(signature->s, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->s, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(Sm2VerifySignatureState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(Sm2VerifySignatureState));

   //Let PA be the public key
   ecProjectify(publicKey->curve, &state->pa, &publicKey->q);

   //Calculate ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
   error = sm2ComputeZa(hashAlgo, &state->hashContext, publicKey->curve,
      &state->pa, id, idLen, state->buffer);

   //Check status code
   if(!error)
   {
      //Let M~ = ZA || M and calculate Hv(M~)
      hashAlgo->init(&state->hashContext);
      hashAlgo->update(&state->hashContext, state->buffer, hashAlgo->digestSize);
      hashAlgo->update(&state->hashContext, message, messageLen);
      hashAlgo->final(&state->hashContext, state->buffer);

      //Let e = Hv(M~)
      error = ecScalarImport(state->e, 8, state->buffer, hashAlgo->digestSize,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Calculate t = (r + s) mod q
      ecScalarAddMod(publicKey->curve, state->t, signature->r, signature->s);

      //Test if t = 0
      if(ecScalarCompInt(state->t, 0, 8) == 0)
      {
         //Verification failed
         error = ERROR_INVALID_SIGNATURE;
      }
      else
      {
         //Convert the public key to projective representation
         ecProjectify(publicKey->curve, &state->pa, &publicKey->q);

         //Calculate the point (x1, y1)=[s]G + [t]PA
         error = ecTwinMul(publicKey->curve, &state->p1, signature->s,
            &publicKey->curve->g, state->t, &state->pa);
      }
   }

   //Check status code
   if(!error)
   {
      //Convert P1 to affine representation
      error = ecAffinify(publicKey->curve, &state->p1, &state->p1);
   }

   //Check status code
   if(!error)
   {
      //Calculate R = (e + x1) mod q
      ecScalarMod(state->r, state->p1.x, 8, publicKey->curve->q, 8);
      ecScalarAddMod(publicKey->curve, state->r, state->r, state->e);

      //Debug message
      TRACE_DEBUG("  R:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->r, 8);

      //Verify that R = r
      if(ecScalarComp(state->r, signature->r, 8) == 0)
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

   //Erase working state
   osMemset(state, 0, sizeof(Sm2VerifySignatureState));

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release working state
   cryptoFreeMem(state);
#endif

   //Return status code
   return error;
}


/**
 * @brief Calculate ZA
 * @param[in] hashAlgo Hash function
 * @param[in] hashContext Hash function context
 * @param[in] curve EC domain parameters
 * @param[in] pa Public key of user A
 * @param[in] ida Distinguishing identifier of user A
 * @param[in] idaLen Length of the identifier
 * @param[out] za Hash value of the distinguishing identifier of user A
 **/

error_t sm2ComputeZa(const HashAlgo *hashAlgo, HashContext *hashContext,
   const EcCurve *curve, const EcPoint3 *pa, const char_t *ida, size_t idaLen,
   uint8_t *za)
{
   error_t error;
   size_t n;
   uint8_t buffer[32];

   //Get the length in octets of the prime modulus
   n = (curve->fieldSize + 7) / 8;

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
   error = ecScalarExport(curve->a, (n + 3) / 4, buffer, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the parameter a
   hashAlgo->update(hashContext, buffer, n);

   //Convert the parameter b to bit string
   error = ecScalarExport(curve->b, (n + 3) / 4, buffer, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the parameter b
   hashAlgo->update(hashContext, buffer, n);

   //Convert the coordinate xG to bit string
   error = ecScalarExport(curve->g.x, (n + 3) / 4, buffer, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the coordinate xG
   hashAlgo->update(hashContext, buffer, n);

   //Convert the coordinate yG to bit string
   error = ecScalarExport(curve->g.y, (n + 3) / 4, buffer, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the coordinate yG
   hashAlgo->update(hashContext, buffer, n);

   //Convert the public key's coordinate xA to bit string
   error = ecScalarExport(pa->x, (n + 3) / 4, buffer, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Digest the public key's coordinate xA
   hashAlgo->update(hashContext, buffer, n);

   //Convert the public key's coordinate yA to bit string
   error = ecScalarExport(pa->y, (n + 3) / 4, buffer, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
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
