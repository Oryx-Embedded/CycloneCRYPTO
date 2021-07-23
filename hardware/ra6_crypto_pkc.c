/**
 * @file ra6_crypto_pkc.c
 * @brief RA6 public-key hardware accelerator
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2021 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.1.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "hw_sce_rsa_private.h"
#include "hw_sce_ecc_private.h"
#include "core/crypto.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ecdsa.h"
#include "mpi/mpi.h"
#include "hardware/ra6_crypto.h"
#include "hardware/ra6_crypto_pkc.h"
#include "debug.h"

//Check crypto library configuration
#if (RA6_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
static Ra6RsaArgs rsaArgs;
static Ra6EcArgs ecArgs;


/**
 * @brief RSA private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] k Required bit length of the modulus n
 * @param[in] e Public exponent (3, 5, 17, 257 or 65537)
 * @param[out] privateKey RSA private key
 * @return Error code
 **/

error_t rsaGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   size_t k, uint_t e, RsaPrivateKey *privateKey)
{
   error_t error;
   fsp_err_t status;

   //Check parameters
   if(k != 2048 || e != 65537 || privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&ra6CryptoMutex);

   //Generate an RSA private key
   status = HW_SCE_RSA_2048KeyGenerate(UINT32_MAX, rsaArgs.d, rsaArgs.n,
      rsaArgs.params);

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //The value of the public exponent is fixed to 65537
      error = mpiSetValue(&privateKey->e, e);

      //Check status code
      if(!error)
      {
         //Copy the private exponent
         error = mpiReadRaw(&privateKey->d, (uint8_t *) rsaArgs.d, 256);
      }

      //Check status code
      if(!error)
      {
         //Copy the modulus
         error = mpiReadRaw(&privateKey->n, (uint8_t *) rsaArgs.n, 256);
      }

      //Check status code
      if(!error)
      {
         //Copy the first factor
         error = mpiReadRaw(&privateKey->p, (uint8_t *) rsaArgs.params + 384,
            128);
      }

      //Check status code
      if(!error)
      {
         //Copy the second factor
         error = mpiReadRaw(&privateKey->q, (uint8_t *) rsaArgs.params + 128,
            128);
      }

      //Check status code
      if(!error)
      {
         //Copy the first factor's CRT exponent
         error = mpiReadRaw(&privateKey->dp, (uint8_t *) rsaArgs.params + 256,
            128);
      }

      //Check status code
      if(!error)
      {
         //Copy the second factor's CRT exponent
         error = mpiReadRaw(&privateKey->dq, (uint8_t *) rsaArgs.params, 128);
      }

      //Check status code
      if(!error)
      {
         //Copy the CRT coefficient
         error = mpiReadRaw(&privateKey->qinv, (uint8_t *) rsaArgs.params + 512,
            128);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief RSA encryption primitive
 *
 * The RSA encryption primitive produces a ciphertext representative from
 * a message representative under the control of a public key
 *
 * @param[in] key RSA public key
 * @param[in] m Message representative
 * @param[out] c Ciphertext representative
 * @return Error code
 **/

error_t rsaep(const RsaPublicKey *key, const Mpi *m, Mpi *c)
{
   error_t error;
   size_t nLen;
   size_t eLen;

   //Retrieve the length of the public key
   nLen = mpiGetByteLength(&key->n);
   eLen = mpiGetByteLength(&key->e);

   //Sanity check
   if(nLen == 0 || eLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The message representative m shall be between 0 and n - 1
   if(mpiCompInt(m, 0) < 0 || mpiComp(m, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Check the length of the public key
   if(nLen <= 256 && eLen <= 4)
   {
      fsp_err_t status;

      //Acquire exclusive access to the SCE7 module
      osAcquireMutex(&ra6CryptoMutex);

      //Set parameters
      mpiWriteRaw(m, (uint8_t *) rsaArgs.m, sizeof(rsaArgs.m));
      mpiWriteRaw(&key->n, (uint8_t *) rsaArgs.n, sizeof(rsaArgs.n));
      mpiWriteRaw(&key->e, (uint8_t *) rsaArgs.e, sizeof(rsaArgs.e));

      //Perform RSA encryption
      status = HW_SCE_RSA_2048PublicKeyEncrypt(rsaArgs.m, rsaArgs.e,
         rsaArgs.n, rsaArgs.c);

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Copy the ciphertext representative
         error = mpiReadRaw(c, (uint8_t *) rsaArgs.c, sizeof(rsaArgs.c));
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the SCE7 module
      osReleaseMutex(&ra6CryptoMutex);
   }
   else
   {
      //Perform modular exponentiation (c = m ^ e mod n)
      error = mpiExpMod(c, m, &key->e, &key->n);
   }

   //Return status code
   return error;
}


/**
 * @brief RSA decryption primitive
 *
 * The RSA decryption primitive recovers the message representative from
 * the ciphertext representative under the control of a private key
 *
 * @param[in] key RSA private key
 * @param[in] c Ciphertext representative
 * @param[out] m Message representative
 * @return Error code
 **/

error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;
   size_t nLen;
   size_t dLen;
   size_t pLen;
   size_t qLen;
   size_t dpLen;
   size_t dqLen;
   size_t qinvLen;

   //Retrieve the length of the private key
   nLen = mpiGetByteLength(&key->n);
   dLen = mpiGetByteLength(&key->d);
   pLen = mpiGetByteLength(&key->p);
   qLen = mpiGetByteLength(&key->q);
   dpLen = mpiGetByteLength(&key->dp);
   dqLen = mpiGetByteLength(&key->dq);
   qinvLen = mpiGetByteLength(&key->qinv);

   //Sanity check
   if(nLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The ciphertext representative c shall be between 0 and n - 1
   if(mpiCompInt(c, 0) < 0 || mpiComp(c, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Check the length of the public key
   if(nLen <= 256 && dLen <= 256)
   {
      fsp_err_t status;

      //Acquire exclusive access to the SCE7 module
      osAcquireMutex(&ra6CryptoMutex);

      //Set parameters
      mpiWriteRaw(c, (uint8_t *) rsaArgs.c, sizeof(rsaArgs.c));
      mpiWriteRaw(&key->n, (uint8_t *) rsaArgs.n, sizeof(rsaArgs.n));
      mpiWriteRaw(&key->d, (uint8_t *) rsaArgs.d, sizeof(rsaArgs.d));

      //Perform RSA decryption
      status = HW_SCE_RSA_2048PrivateKeyDecrypt(rsaArgs.c, rsaArgs.d,
         rsaArgs.n, rsaArgs.m);

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Copy the message representative
         error = mpiReadRaw(m, (uint8_t *) rsaArgs.m, sizeof(rsaArgs.m));
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the SCE7 module
      osReleaseMutex(&ra6CryptoMutex);
   }
   else if(nLen > 0 && pLen > 0 && qLen > 0 && dpLen > 0 && dqLen > 0 &&
      qinvLen > 0)
   {
      Mpi m1;
      Mpi m2;
      Mpi h;

      //Initialize multiple-precision integers
      mpiInit(&m1);
      mpiInit(&m2);
      mpiInit(&h);

      //Check the length of p, q, dp and dq
      if(pLen <= 256 && qLen <= 256 && dpLen <= 256 && dqLen <= 256)
      {
         fsp_err_t status;

         //Reduce c first
         error = mpiMod(&h, c, &key->p);

         //Check status code
         if(!error)
         {
            //Acquire exclusive access to the SCE7 module
            osAcquireMutex(&ra6CryptoMutex);

            //Set parameters
            mpiWriteRaw(&h, (uint8_t *) rsaArgs.c, sizeof(rsaArgs.c));
            mpiWriteRaw(&key->p, (uint8_t *) rsaArgs.n, sizeof(rsaArgs.n));
            mpiWriteRaw(&key->dp, (uint8_t *) rsaArgs.d, sizeof(rsaArgs.d));

            //Compute m1 = c ^ dP mod p
            status = HW_SCE_RSA_2048PrivateKeyDecrypt(rsaArgs.c, rsaArgs.d,
               rsaArgs.n, rsaArgs.m);

            //Check status code
            if(status == FSP_SUCCESS)
            {
               error = mpiReadRaw(&m1, (uint8_t *) rsaArgs.m,
                  sizeof(rsaArgs.m));
            }
            else
            {
               error = ERROR_FAILURE;
            }

            //Release exclusive access to the SCE7 module
            osReleaseMutex(&ra6CryptoMutex);
         }

         //Check status code
         if(!error)
         {
            error = mpiMod(&h, c, &key->q);
         }

         //Check status code
         if(!error)
         {
            //Acquire exclusive access to the SCE7 module
            osAcquireMutex(&ra6CryptoMutex);

            //Set parameters
            mpiWriteRaw(&h, (uint8_t *) rsaArgs.c, sizeof(rsaArgs.c));
            mpiWriteRaw(&key->q, (uint8_t *) rsaArgs.n, sizeof(rsaArgs.n));
            mpiWriteRaw(&key->dq, (uint8_t *) rsaArgs.d, sizeof(rsaArgs.d));

            //Compute m2 = c ^ dQ mod q
            status = HW_SCE_RSA_2048PrivateKeyDecrypt(rsaArgs.c, rsaArgs.d,
               rsaArgs.n, rsaArgs.m);

            //Check status code
            if(status == FSP_SUCCESS)
            {
               error = mpiReadRaw(&m2, (uint8_t *) rsaArgs.m,
                  sizeof(rsaArgs.m));
            }
            else
            {
               error = ERROR_FAILURE;
            }

            //Release exclusive access to the SCE7 module
            osReleaseMutex(&ra6CryptoMutex);
         }
      }
      else
      {
         //Compute m1 = c ^ dP mod p
         error = mpiExpMod(&m1, c, &key->dp, &key->p);

         //Compute m2 = c ^ dQ mod q
         if(!error)
         {
            error = mpiExpMod(&m2, c, &key->dq, &key->q);
         }
      }

      //Let h = (m1 - m2) * qInv mod p
      if(!error)
      {
         error = mpiSub(&h, &m1, &m2);
      }

      if(!error)
      {
         error = mpiMulMod(&h, &h, &key->qinv, &key->p);
      }

      //Let m = m2 + q * h
      if(!error)
      {
         error = mpiMul(m, &key->q, &h);
      }

      if(!error)
      {
         error = mpiAdd(m, m, &m2);
      }

      //Free previously allocated memory
      mpiFree(&m1);
      mpiFree(&m2);
      mpiFree(&h);
   }
   else if(nLen > 0 && dLen > 0)
   {
      //Let m = c ^ d mod n
      error = mpiExpMod(m, c, &key->d, &key->n);
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
 * @brief Recover affine representation
 * @param[in] params EC domain parameters
 * @param[out] r Affine representation of the point
 * @param[in] s Projective representation of the point
 * @return Error code
 **/

error_t ecAffinify(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s)
{
   //The point is already normalized
   return ecCopy(r, s);
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
   fsp_err_t status;
   size_t n;
   size_t modLen;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);

   //Compute the length of the scalar
   if(modLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&ra6CryptoMutex);

   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Set scalar value
   mpiWriteRaw(d, (uint8_t *) ecArgs.d, n);

   //Set input point
   mpiWriteRaw(&s->x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&s->y, (uint8_t *) ecArgs.g + n, n);

   //Perform scalar multiplication
   if(n == 32)
   {
      status = HW_SCE_ECC_256ScalarMultiplication(ecArgs.params, ecArgs.d,
         ecArgs.g, ecArgs.q);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384ScalarMultiplication(ecArgs.params, ecArgs.d,
         ecArgs.g, ecArgs.q);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the x-coordinate of the result
      error = mpiReadRaw(&r->x, (uint8_t *) ecArgs.q, n);

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = mpiReadRaw(&r->y, (uint8_t *) ecArgs.q + n, n);
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

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief EC key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[out] privateKey EC private key
 * @param[out] publicKey EC public key
 * @return Error code
 **/

error_t ecGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, Mpi *privateKey, EcPoint *publicKey)
{
   error_t error;
   fsp_err_t status;
   size_t n;
   size_t modLen;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);

   //Compute the length of the scalar
   if(modLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&ra6CryptoMutex);

   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Set base point
   mpiWriteRaw(&params->g.x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&params->g.y, (uint8_t *) ecArgs.g + n, n);

   //Generate an EC key pair
   if(n == 32)
   {
      status = HW_SCE_ECC_256GenerateKey(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.q);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384GenerateKey(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.q);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the private key
      error = mpiReadRaw(privateKey, (uint8_t *) ecArgs.d, n);

      //Check status code
      if(!error)
      {
         //Copy the x-coordinate of the public key
         error = mpiReadRaw(&publicKey->x, (uint8_t *) ecArgs.q, n);
      }

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the public key
         error = mpiReadRaw(&publicKey->y, (uint8_t *) ecArgs.q + n, n);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&ra6CryptoMutex);

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

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo,
   void *prngContext, const EcDomainParameters *params, const Mpi *privateKey,
   const uint8_t *digest, size_t digestLen, EcdsaSignature *signature)
{
   error_t error;
   fsp_err_t status;
   size_t n;
   size_t modLen;
   size_t orderLen;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);
   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&params->q);

   //Compute the length of the scalar
   if(modLen <= 32 && orderLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48 && orderLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&ra6CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.h, 0, n);
   osMemcpy((uint8_t *) ecArgs.h + n - digestLen, digest, digestLen);

   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Set base point
   mpiWriteRaw(&params->g.x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&params->g.y, (uint8_t *) ecArgs.g + n, n);

   //Set private key
   mpiWriteRaw(privateKey, (uint8_t *) ecArgs.d, n);

   //Generate ECDSA signature
   if(n == 32)
   {
      status = HW_SCE_ECC_256GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.h, ecArgs.r, ecArgs.s);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.h, ecArgs.r, ecArgs.s);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the first part of the ECDSA signature
      error = mpiReadRaw(&signature->r, (uint8_t *) ecArgs.r, n);

      //Check status code
      if(!error)
      {
         //Copy the second part of the ECDSA signature
         error = mpiReadRaw(&signature->s, (uint8_t *) ecArgs.s, n);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&ra6CryptoMutex);

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
   const EcPoint *publicKey, const uint8_t *digest, size_t digestLen,
   const EcdsaSignature *signature)
{
   fsp_err_t status;
   size_t n;
   size_t modLen;
   size_t orderLen;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);
   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&params->q);

   //Compute the length of the scalar
   if(modLen <= 32 && orderLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48 && orderLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&ra6CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.h, 0, n);
   osMemcpy((uint8_t *) ecArgs.h + n - digestLen, digest, digestLen);

   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Set base point
   mpiWriteRaw(&params->g.x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&params->g.y, (uint8_t *) ecArgs.g + n, n);

   //Set public key
   mpiWriteRaw(&publicKey->x, (uint8_t *) ecArgs.q, n);
   mpiWriteRaw(&publicKey->y, ((uint8_t *) ecArgs.q) + n, n);

   //Set signature
   mpiWriteRaw(&signature->r, (uint8_t *) ecArgs.r, n);
   mpiWriteRaw(&signature->s, (uint8_t *) ecArgs.s, n);

   //Verify ECDSA signature
   if(n == 32)
   {
      status = HW_SCE_ECC_256VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.h, ecArgs.r, ecArgs.s);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.h, ecArgs.r, ecArgs.s);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
}

#endif
