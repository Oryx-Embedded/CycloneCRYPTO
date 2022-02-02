/**
 * @file stm32u5xx_crypto_pkc.c
 * @brief STM32U5 public-key hardware accelerator (PKA)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.1.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "stm32u5xx.h"
#include "stm32u5xx_hal.h"
#include "stm32u5xx_hal_pka.h"
#include "core/crypto.h"
#include "hardware/stm32u5xx/stm32u5xx_crypto.h"
#include "hardware/stm32u5xx/stm32u5xx_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ecdsa.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32U5XX_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variable
static Stm32u5xxRsaArgs rsaArgs;
static Stm32u5xxEccArgs eccArgs;
static PKA_HandleTypeDef PKA_Handle;


/**
 * @brief PKA module initialization
 * @return Error code
 **/

error_t pkaInit(void)
{
   HAL_StatusTypeDef status;

   //Enable PKA peripheral clock
   __HAL_RCC_PKA_CLK_ENABLE();

   //Set instance
   PKA_Handle.Instance = PKA;

   //Reset PKA module
   status = HAL_PKA_DeInit(&PKA_Handle);

   //Check status code
   if(status == HAL_OK)
   {
      //Initialize PKA module
      status = HAL_PKA_Init(&PKA_Handle);
   }

   //Return status code
   return (status == HAL_OK) ? NO_ERROR : ERROR_FAILURE;
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
   size_t modLen;
   size_t expLen;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(p);
   //Retrieve the length of the exponent, in bytes
   expLen = mpiGetByteLength(e);

   //Check the length of the operands
   if(modLen <= STM32U5XX_MAX_ROS && expLen <= STM32U5XX_MAX_ROS)
   {
      //Reduce the operand first
      error = mpiMod(r, a, p);

      //Check status code
      if(!error)
      {
         HAL_StatusTypeDef status;
         PKA_ModExpInTypeDef modExpIn;

         //Acquire exclusive access to the PKA module
         osAcquireMutex(&stm32u5xxCryptoMutex);

         //Copy operand
         mpiWriteRaw(r, rsaArgs.a, modLen);
         //Copy exponent
         mpiWriteRaw(e, rsaArgs.e, expLen);
         //Copy modulus
         mpiWriteRaw(p, rsaArgs.p, modLen);

         //Set input parameters
         modExpIn.expSize = expLen;
         modExpIn.OpSize = modLen;
         modExpIn.pExp = rsaArgs.e;
         modExpIn.pOp1 = rsaArgs.a;
         modExpIn.pMod = rsaArgs.p;

         //Perform modular exponentiation
         status = HAL_PKA_ModExp(&PKA_Handle, &modExpIn, HAL_MAX_DELAY);

         //Check status code
         if(status == HAL_OK)
         {
            //Get the result of the modular exponentiation
            HAL_PKA_ModExp_GetResult(&PKA_Handle, rsaArgs.a);

            //Copy resulting integer
            error = mpiReadRaw(r, rsaArgs.a, modLen);
         }
         else
         {
            //Report an error
            error = ERROR_FAILURE;
         }

         //Clear PKA RAM
         HAL_PKA_RAMReset(&PKA_Handle);

         //Release exclusive access to the PKA module
         osReleaseMutex(&stm32u5xxCryptoMutex);
      }
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
 * @brief Modular exponentiation with CRT
 * @param[in] key RSA public key
 * @param[in] m Message representative
 * @param[out] c Ciphertext representative
 * @return Error code
 **/

error_t pkaRsaCrtExp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;
   size_t nLen;
   size_t pLen;
   size_t qLen;
   size_t dpLen;
   size_t dqLen;
   size_t qinvLen;

   //Retrieve the length of the private key
   nLen = mpiGetByteLength(&key->n);
   pLen = mpiGetByteLength(&key->p);
   qLen = mpiGetByteLength(&key->q);
   dpLen = mpiGetByteLength(&key->dp);
   dqLen = mpiGetByteLength(&key->dq);
   qinvLen = mpiGetByteLength(&key->qinv);

   //Check the length of the operands
   if(nLen <= STM32U5XX_MAX_ROS && pLen <= (nLen / 2) && qLen <= (nLen / 2) &&
      dpLen <= (nLen / 2) && dqLen <= (nLen / 2) && qinvLen <= (nLen / 2))
   {
      HAL_StatusTypeDef status;
      PKA_RSACRTExpInTypeDef rsaCrtExpIn;

      //Acquire exclusive access to the PKA module
      osAcquireMutex(&stm32u5xxCryptoMutex);

      //Copy private key
      mpiWriteRaw(&key->p, rsaArgs.p, nLen / 2);
      mpiWriteRaw(&key->q, rsaArgs.q, nLen / 2);
      mpiWriteRaw(&key->dp, rsaArgs.dp, nLen / 2);
      mpiWriteRaw(&key->dq, rsaArgs.dq, nLen / 2);
      mpiWriteRaw(&key->qinv, rsaArgs.qinv, nLen / 2);

      //Copy ciphertext representative
      mpiWriteRaw(c, rsaArgs.a, nLen);

      //Set input parameters
      rsaCrtExpIn.size = nLen;
      rsaCrtExpIn.pOpDp = rsaArgs.dp;
      rsaCrtExpIn.pOpDq = rsaArgs.dq;
      rsaCrtExpIn.pOpQinv = rsaArgs.qinv;
      rsaCrtExpIn.pPrimeP = rsaArgs.p;
      rsaCrtExpIn.pPrimeQ = rsaArgs.q;
      rsaCrtExpIn.popA = rsaArgs.a;

      //Perform modular exponentiation (with CRT)
      status = HAL_PKA_RSACRTExp(&PKA_Handle, &rsaCrtExpIn, HAL_MAX_DELAY);

      //Check status code
      if(status == HAL_OK)
      {
         //Get the result of the modular exponentiation
         HAL_PKA_RSACRTExp_GetResult(&PKA_Handle, rsaArgs.a);

         //Copy the message representative
         error = mpiReadRaw(m, rsaArgs.a, nLen);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Clear PKA RAM
      HAL_PKA_RAMReset(&PKA_Handle);

      //Release exclusive access to the PKA module
      osReleaseMutex(&stm32u5xxCryptoMutex);
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
 * @brief RSA decryption primitive
 * @param[in] key RSA private key
 * @param[in] c Ciphertext representative
 * @param[out] m Message representative
 * @return Error code
 **/

error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;

   //The ciphertext representative c shall be between 0 and n - 1
   if(mpiCompInt(c, 0) < 0 || mpiComp(c, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Use the Chinese remainder algorithm?
   if(mpiGetLength(&key->n) > 0 && mpiGetLength(&key->p) > 0 &&
      mpiGetLength(&key->q) > 0 && mpiGetLength(&key->dp) > 0 &&
      mpiGetLength(&key->dq) > 0 && mpiGetLength(&key->qinv) > 0)
   {
      //Perform modular exponentiation (with CRT)
      error = pkaRsaCrtExp(key, c, m);
   }
   else if(mpiGetLength(&key->n) > 0 && mpiGetLength(&key->d) > 0)
   {
      //Perform modular exponentiation (without CRT)
      error = mpiExpMod(m, c, &key->d, &key->n);
   }
   else
   {
      //Invalid parameters
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Scalar multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMult(const EcDomainParameters *params, EcPoint *r, const Mpi *d,
   const EcPoint *s)
{
   error_t error;
   size_t modLen;
   size_t orderLen;
   size_t scalarLen;
   HAL_StatusTypeDef status;
   PKA_ECCMulInTypeDef eccMulIn;
   PKA_ECCMulOutTypeDef eccMulOut;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);
   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&params->q);

   //Retrieve the length of the scalar, in bytes
   scalarLen = mpiGetByteLength(d);
   scalarLen = MAX(scalarLen, orderLen);

   //Check the length of the operands
   if(modLen <= STM32U5XX_MAX_EOS && scalarLen <= STM32U5XX_MAX_EOS)
   {
      //Acquire exclusive access to the PKA module
      osAcquireMutex(&stm32u5xxCryptoMutex);

      //Copy domain parameters
      mpiWriteRaw(&params->p, eccArgs.p, modLen);
      mpiWriteRaw(&params->a, eccArgs.a, modLen);
      mpiWriteRaw(&params->b, eccArgs.b, modLen);
      mpiWriteRaw(&params->q, eccArgs.q, scalarLen);

      //Copy scalar
      mpiWriteRaw(d, eccArgs.d, scalarLen);

      //Copy input point
      mpiWriteRaw(&s->x, eccArgs.gx, modLen);
      mpiWriteRaw(&s->y, eccArgs.gy, modLen);

      //Set input parameters
      eccMulIn.scalarMulSize = scalarLen;
      eccMulIn.modulusSize = modLen;
      eccMulIn.coefSign = 0;
      eccMulIn.coefA = eccArgs.a;
      eccMulIn.coefB = eccArgs.b;
      eccMulIn.modulus = eccArgs.p;
      eccMulIn.pointX = eccArgs.gx;
      eccMulIn.pointY = eccArgs.gy;
      eccMulIn.scalarMul = eccArgs.d;
      eccMulIn.primeOrder = eccArgs.q;

      //Perform scalar multiplication
      status = HAL_PKA_ECCMul(&PKA_Handle, &eccMulIn, HAL_MAX_DELAY);

      //Check status code
      if(status == HAL_OK)
      {
         //Set output parameters
         eccMulOut.modulusSize = modLen;
         eccMulOut.ptX = eccArgs.qx;
         eccMulOut.ptY = eccArgs.qy;

         //Get the output point
         HAL_PKA_ECCMul_GetResult(&PKA_Handle, &eccMulOut);

         //Copy the x-coordinate of the result
         error = mpiReadRaw(&r->x, eccArgs.qx, modLen);

         //Check status code
         if(!error)
         {
            //Copy the y-coordinate of the result
            error = mpiReadRaw(&r->y, eccArgs.qy, modLen);
         }

         //Check status code
         if(!error)
         {
            //Set the z-coordinate of the result
            error = mpiSetValue(&r->z, 1);
         }
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Clear PKA RAM
      HAL_PKA_RAMReset(&PKA_Handle);

      //Release exclusive access to the PKA module
      osReleaseMutex(&stm32u5xxCryptoMutex);
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
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, const EcPrivateKey *privateKey,
   const uint8_t *digest, size_t digestLen, EcdsaSignature *signature)
{
   error_t error;
   size_t modLen;
   size_t orderLen;
   Mpi k;
   HAL_StatusTypeDef status;
   PKA_ECDSASignInTypeDef ecdsaSignIn;
   PKA_ECDSASignOutTypeDef ecdsaSignOut;

   //Check parameters
   if(params == NULL || privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);
   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&params->q);

   //Check the length of the operands
   if(modLen > STM32U5XX_MAX_EOS || orderLen > STM32U5XX_MAX_EOS)
      return ERROR_FAILURE;

   //Initialize multiple precision integers
   mpiInit(&k);

   //Generate a random number k such as 0 < k < q - 1
   error = mpiRandRange(&k, &params->q, prngAlgo, prngContext);

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the PKA module
      osAcquireMutex(&stm32u5xxCryptoMutex);

      //Copy domain parameters
      mpiWriteRaw(&params->p, eccArgs.p, modLen);
      mpiWriteRaw(&params->a, eccArgs.a, modLen);
      mpiWriteRaw(&params->b, eccArgs.b, modLen);
      mpiWriteRaw(&params->g.x, eccArgs.gx, modLen);
      mpiWriteRaw(&params->g.y, eccArgs.gy, modLen);
      mpiWriteRaw(&params->q, eccArgs.q, orderLen);

      //Copy private key
      mpiWriteRaw(&privateKey->d, eccArgs.d, orderLen);

      //Copy random integer
      mpiWriteRaw(&k, eccArgs.k, orderLen);

      //Keep the leftmost bits of the hash value
      digestLen = MIN(digestLen, orderLen);

      //Pad the digest with leading zeroes if necessary
      osMemset(eccArgs.h, 0, orderLen);
      osMemcpy(eccArgs.h + orderLen - digestLen, digest, digestLen);

      //Set input parameters
      ecdsaSignIn.primeOrderSize = orderLen;
      ecdsaSignIn.modulusSize = modLen;
      ecdsaSignIn.coefSign = 0;
      ecdsaSignIn.coef = eccArgs.a;
      ecdsaSignIn.coefB = eccArgs.b;
      ecdsaSignIn.modulus = eccArgs.p;
      ecdsaSignIn.integer = eccArgs.k;
      ecdsaSignIn.basePointX = eccArgs.gx;
      ecdsaSignIn.basePointY = eccArgs.gy;
      ecdsaSignIn.hash = eccArgs.h;
      ecdsaSignIn.privateKey = eccArgs.d;
      ecdsaSignIn.primeOrder = eccArgs.q;

      //Generate ECDSA signature
      status = HAL_PKA_ECDSASign(&PKA_Handle, &ecdsaSignIn, HAL_MAX_DELAY);

      //Check status code
      if(status == HAL_OK)
      {
         //Set output parameters
         ecdsaSignOut.primeOrderSize = orderLen;
         ecdsaSignOut.RSign = eccArgs.r;
         ecdsaSignOut.SSign = eccArgs.s;

         //Get the resulting ECDSA signature
         HAL_PKA_ECDSASign_GetResult(&PKA_Handle, &ecdsaSignOut, NULL);

         //Copy integer R
         error = mpiReadRaw(&signature->r, eccArgs.r, orderLen);

         //Check status code
         if(!error)
         {
            //Copy integer S
            error = mpiReadRaw(&signature->s, eccArgs.s, orderLen);
         }
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Clear PKA RAM
      HAL_PKA_RAMReset(&PKA_Handle);

      //Release exclusive access to the PKA module
      osReleaseMutex(&stm32u5xxCryptoMutex);
   }

   //Release multiple precision integer
   mpiFree(&k);

   //Return status code
   return error;
}


/**
 * @brief ECDSA signature verification
 * @param[in] params EC domain parameters
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaVerifySignature(const EcDomainParameters *params,
   const EcPublicKey *publicKey, const uint8_t *digest, size_t digestLen,
   const EcdsaSignature *signature)
{
   error_t error;
   size_t modLen;
   size_t orderLen;
   HAL_StatusTypeDef status;
   PKA_ECDSAVerifInTypeDef ecdsaVerifIn;

   //Check parameters
   if(params == NULL || publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

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

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);
   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&params->q);

   //Check the length of the operands
   if(modLen > STM32U5XX_MAX_EOS || orderLen > STM32U5XX_MAX_EOS)
      return ERROR_FAILURE;

   //Acquire exclusive access to the PKA module
   osAcquireMutex(&stm32u5xxCryptoMutex);

   //Copy domain parameters
   mpiWriteRaw(&params->p, eccArgs.p, modLen);
   mpiWriteRaw(&params->a, eccArgs.a, modLen);
   mpiWriteRaw(&params->g.x, eccArgs.gx, modLen);
   mpiWriteRaw(&params->g.y, eccArgs.gy, modLen);
   mpiWriteRaw(&params->q, eccArgs.q, orderLen);

   //Copy public key
   mpiWriteRaw(&publicKey->q.x, eccArgs.qx, modLen);
   mpiWriteRaw(&publicKey->q.y, eccArgs.qy, modLen);

   //Copy the signature
   mpiWriteRaw(&signature->r, eccArgs.r, orderLen);
   mpiWriteRaw(&signature->s, eccArgs.s, orderLen);

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Pad the digest with leading zeroes if necessary
   osMemset(eccArgs.h, 0, orderLen);
   osMemcpy(eccArgs.h + orderLen - digestLen, digest, digestLen);

   //Set input parameters
   ecdsaVerifIn.primeOrderSize = orderLen;
   ecdsaVerifIn.modulusSize = modLen;
   ecdsaVerifIn.coefSign = 0;
   ecdsaVerifIn.coef = eccArgs.a;
   ecdsaVerifIn.modulus = eccArgs.p;
   ecdsaVerifIn.basePointX = eccArgs.gx;
   ecdsaVerifIn.basePointY = eccArgs.gy;
   ecdsaVerifIn.pPubKeyCurvePtX = eccArgs.qx;
   ecdsaVerifIn.pPubKeyCurvePtY = eccArgs.qy;
   ecdsaVerifIn.RSign = eccArgs.r;
   ecdsaVerifIn.SSign = eccArgs.s;
   ecdsaVerifIn.hash = eccArgs.h;
   ecdsaVerifIn.primeOrder = eccArgs.q;

   //Verify ECDSA signature
   status = HAL_PKA_ECDSAVerif(&PKA_Handle, &ecdsaVerifIn, HAL_MAX_DELAY);

   //Check status code
   if(status == HAL_OK)
   {
      //Test if the ECDSA signature is valid
      if(HAL_PKA_ECDSAVerif_IsValidSignature(&PKA_Handle) == 1)
      {
         error = NO_ERROR;
      }
      else
      {
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Clear PKA RAM
   HAL_PKA_RAMReset(&PKA_Handle);

   //Release exclusive access to the PKA module
   osReleaseMutex(&stm32u5xxCryptoMutex);

   //Return status code
   return error;
}

#endif
