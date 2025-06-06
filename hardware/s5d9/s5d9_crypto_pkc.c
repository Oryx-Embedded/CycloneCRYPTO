/**
 * @file s5d9_crypto_pkc.c
 * @brief Synergy S5D9 public-key hardware accelerator
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
#include "hw_sce_private.h"
#include "hw_sce_rsa_private.h"
#include "hw_sce_ecc_private.h"
#include "core/crypto.h"
#include "hardware/s5d9/s5d9_crypto.h"
#include "hardware/s5d9/s5d9_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/ecdsa.h"
#include "debug.h"

//Check crypto library configuration
#if (S5D9_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
static Ra6RsaArgs rsaArgs;
static Ra6EcArgs ecArgs;

#if (MPI_SUPPORT == ENABLED)

/**
 * @brief Modular exponentiation (fast calculation)
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t mpiExpModFast(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   ssp_err_t status;
   size_t n;
   size_t aLen;
   size_t eLen;
   size_t pLen;

   //Get the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Get the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Get the length of the modulus, in bytes
   pLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 2048 bits
   if((aLen <= 128 && eLen <= 4 && pLen <= 128) ||
      (aLen <= 256 && eLen <= 4 && pLen <= 256))
   {
      //Select appropriate scalar length
      n = (pLen <= 128) ? 128 : 256;

      //Acquire exclusive access to the SCE7 module
      osAcquireMutex(&s5d9CryptoMutex);

      //Format message representative
      mpiWriteRaw(a, (uint8_t *) rsaArgs.m, n);

      //Format public key
      mpiWriteRaw(p, (uint8_t *) rsaArgs.n, n);
      mpiWriteRaw(e, (uint8_t *) rsaArgs.e, 4);

      //Perform RSA encryption
      if(n == 128)
      {
         status = HW_SCE_RSA_1024PublicEncrypt(0, rsaArgs.m, rsaArgs.e,
            rsaArgs.n, rsaArgs.c);
      }
      else if(n == 256)
      {
         status = HW_SCE_RSA_2048PublicEncrypt(0, rsaArgs.m, rsaArgs.e,
            rsaArgs.n, rsaArgs.c);
      }
      else
      {
         status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }

      //Check status code
      if(status == SSP_SUCCESS)
      {
         //Copy the ciphertext representative
         error = mpiReadRaw(r, (uint8_t *) rsaArgs.c, n);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the SCE7 module
      osReleaseMutex(&s5d9CryptoMutex);
   }
   else
   {
      //Perform modular exponentiation (r = a ^ e mod p)
      error = mpiExpModRegular(r, a, e, p);
   }

   //Return status code
   return error;
}


/**
 * @brief Modular exponentiation (regular calculation)
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t mpiExpModRegular(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   ssp_err_t status;
   size_t n;
   size_t aLen;
   size_t eLen;
   size_t pLen;

   //Get the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Get the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Get the length of the modulus, in bytes
   pLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 2048 bits
   if((aLen <= 128 && eLen <= 128 && pLen <= 128) ||
      (aLen <= 256 && eLen <= 256 && pLen <= 256))
   {
      //Select appropriate scalar length
      n = (pLen <= 128) ? 128 : 256;

      //Acquire exclusive access to the SCE7 module
      osAcquireMutex(&s5d9CryptoMutex);

      //Format ciphertext representative
      mpiWriteRaw(a, (uint8_t *) rsaArgs.c, n);

      //Format private key
      mpiWriteRaw(p, (uint8_t *) rsaArgs.n, n);
      mpiWriteRaw(e, (uint8_t *) rsaArgs.d, n);

      //Perform RSA decryption
      if(n == 128)
      {
         status = HW_SCE_RSA_1024PrivateKeyDecrypt(0, rsaArgs.c, rsaArgs.d,
            rsaArgs.n, rsaArgs.m);
      }
      else if(n == 256)
      {
         status = HW_SCE_RSA_2048PrivateKeyDecrypt(0, rsaArgs.c, rsaArgs.d,
            rsaArgs.n, rsaArgs.m);
      }
      else
      {
         status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }

      //Check status code
      if(status == SSP_SUCCESS)
      {
         //Copy the message representative
         error = mpiReadRaw(r, (uint8_t *) rsaArgs.m, n);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the SCE7 module
      osReleaseMutex(&s5d9CryptoMutex);
   }
   else
   {
      //Perform modular exponentiation (r = a ^ e mod p)
      error = mpiExpMod(r, a, e, p);
   }

   //Return status code
   return error;
}

#endif
#if (RSA_SUPPORT == ENABLED)

/**
 * @brief RSA private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] k Required bit length of the modulus n (must be 1024 or 2048)
 * @param[in] e Public exponent (must be 65537)
 * @param[out] privateKey RSA private key
 * @return Error code
 **/

error_t rsaGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   size_t k, uint_t e, RsaPrivateKey *privateKey)
{
   error_t error;
   ssp_err_t status;
   size_t n;

   //Check parameters
   if(e != 65537 || privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s5d9CryptoMutex);

   //Check the length of the modulus
   if(k == 1024)
   {
      //Generate a 1024-bit RSA private key
      status = HW_SCE_RSA_1024KeyGenerate(UINT32_MAX, rsaArgs.d, rsaArgs.n,
         rsaArgs.params);
   }
   else if(k == 2048)
   {
      //Generate a 2048-bit RSA private key
      status = HW_SCE_RSA_2048KeyGenerate(UINT32_MAX, rsaArgs.d, rsaArgs.n,
         rsaArgs.params);
   }
   else
   {
      //Report an error
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == SSP_SUCCESS)
   {
      //Compute the length of the modulus, in bytes
      k = k / 8;
      //Compute the length of the CRT factors, in bytes
      n = k / 2;

      //The value of the public exponent is fixed to 65537
      error = mpiSetValue(&privateKey->e, e);

      //Check status code
      if(!error)
      {
         //Copy the private exponent
         error = mpiReadRaw(&privateKey->d, (uint8_t *) rsaArgs.d, k);
      }

      //Check status code
      if(!error)
      {
         //Copy the modulus
         error = mpiReadRaw(&privateKey->n, (uint8_t *) rsaArgs.n, k);
      }

      //Check status code
      if(!error)
      {
         //Copy the first factor
         error = mpiReadRaw(&privateKey->p,
            (uint8_t *) rsaArgs.params + n * 3, n);
      }

      //Check status code
      if(!error)
      {
         //Copy the second factor
         error = mpiReadRaw(&privateKey->q,
            (uint8_t *) rsaArgs.params + n, n);
      }

      //Check status code
      if(!error)
      {
         //Copy the first factor's CRT exponent
         error = mpiReadRaw(&privateKey->dp,
            (uint8_t *) rsaArgs.params + n * 2, n);
      }

      //Check status code
      if(!error)
      {
         //Copy the second factor's CRT exponent
         error = mpiReadRaw(&privateKey->dq,
            (uint8_t *) rsaArgs.params, n);
      }

      //Check status code
      if(!error)
      {
         //Copy the CRT coefficient
         error = mpiReadRaw(&privateKey->qinv,
            (uint8_t *) rsaArgs.params + n * 4, n);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s5d9CryptoMutex);

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

   //Get the length of the private key
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

   //Check the length of the private key
   if(nLen <= 128 && dLen <= 128)
   {
      //Let m = c ^ d mod n
      error = mpiExpModRegular(m, c, &key->d, &key->n);
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

      //Compute m1 = c ^ dP mod p
      error = mpiMod(&m1, c, &key->p);

      if(!error)
      {
         error = mpiExpModRegular(&m1, &m1, &key->dp, &key->p);
      }

      //Compute m2 = c ^ dQ mod q
      if(!error)
      {
         error = mpiMod(&m2, c, &key->q);
      }

      if(!error)
      {
         error = mpiExpModRegular(&m2, &m2, &key->dq, &key->q);
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
      error = mpiExpModRegular(m, c, &key->d, &key->n);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}

#endif
#if (EC_SUPPORT == ENABLED)

/**
 * @brief EC key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] curve Elliptic curve parameters
 * @param[out] privateKey EC private key
 * @param[out] publicKey EC public key (optional parameter)
 * @return Error code
 **/

error_t ecGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EcPrivateKey *privateKey, EcPublicKey *publicKey)
{
   error_t error;
   ssp_err_t status;
   size_t n;
   size_t modLen;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;

   //Compute the length of the scalar
   if(modLen <= 24)
   {
      n = 24;
   }
   else if(modLen <= 28)
   {
      n = 28;
   }
   else if(modLen <= 32)
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
   osAcquireMutex(&s5d9CryptoMutex);

   //Set domain parameters
   ecScalarExport(curve->a, n / 4, (uint8_t *) ecArgs.params, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->b, n / 4, (uint8_t *) ecArgs.params + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->p, n / 4, (uint8_t *) ecArgs.params + n * 2, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->q, n / 4, (uint8_t *) ecArgs.params + n * 3, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set base point
   ecScalarExport(curve->g.x, n / 4, (uint8_t *) ecArgs.g, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->g.y, n / 4, (uint8_t *) ecArgs.g + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Generate an EC key pair
   if(n == 24)
   {
      status = HW_SCE_ECC_192GenerateKey(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.q);
   }
   else if(n == 28)
   {
      status = HW_SCE_ECC_224GenerateKey(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.q);
   }
   else if(n == 32)
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
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == SSP_SUCCESS)
   {
      //Save elliptic curve parameters
      privateKey->curve = curve;
      privateKey->q.curve = curve;

      //Copy the private key
      error = ecScalarImport(privateKey->d, EC_MAX_ORDER_SIZE,
         (uint8_t *) ecArgs.d, n, EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Check status code
      if(!error)
      {
         //Copy the x-coordinate of the public key
         error = ecScalarImport(privateKey->q.q.x, EC_MAX_MODULUS_SIZE,
            (uint8_t *) ecArgs.q, n, EC_SCALAR_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the public key
         error = ecScalarImport(privateKey->q.q.y, EC_MAX_MODULUS_SIZE,
            (uint8_t *) ecArgs.q + n, n, EC_SCALAR_FORMAT_BIG_ENDIAN);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s5d9CryptoMutex);

   //Check status code
   if(!error)
   {
      //The parameter is optional
      if(publicKey != NULL)
      {
         //Copy the resulting public key
         *publicKey = privateKey->q;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Scalar multiplication (fast calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMulFast(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s)
{
   //Compute R = d.S
   return ecMulRegular(curve, r, d, s);
}


/**
 * @brief Scalar multiplication (regular calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < q
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMulRegular(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s)
{
   error_t error;
   ssp_err_t status;
   size_t n;
   size_t modLen;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;

   //Compute the length of the scalar
   if(modLen <= 24)
   {
      n = 24;
   }
   else if(modLen <= 28)
   {
      n = 28;
   }
   else if(modLen <= 32)
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
   osAcquireMutex(&s5d9CryptoMutex);

   //Set domain parameters
   ecScalarExport(curve->a, n / 4, (uint8_t *) ecArgs.params, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->b, n / 4, (uint8_t *) ecArgs.params + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->p, n / 4, (uint8_t *) ecArgs.params + n * 2, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->q, n / 4, (uint8_t *) ecArgs.params + n * 3, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set scalar value
   ecScalarExport(d, n / 4, (uint8_t *) ecArgs.d, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set input point
   ecScalarExport(s->x, n / 4, (uint8_t *) ecArgs.g, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(s->y, n / 4, (uint8_t *) ecArgs.g + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Perform scalar multiplication
   if(n == 24)
   {
      status = HW_SCE_ECC_192ScalarMultiplication(ecArgs.params, ecArgs.d,
         ecArgs.g, ecArgs.q);
   }
   else if(n == 28)
   {
      status = HW_SCE_ECC_224ScalarMultiplication(ecArgs.params, ecArgs.d,
         ecArgs.g, ecArgs.q);
   }
   else if(n == 32)
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
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == SSP_SUCCESS)
   {
      //Copy the x-coordinate of the result
      error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE, (uint8_t *) ecArgs.q,
         n, EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE,
            (uint8_t *) ecArgs.q + n, n, EC_SCALAR_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Set the z-coordinate of the result
         ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s5d9CryptoMutex);

   //Return status code
   return error;
}

#endif
#if (ECDSA_SUPPORT == ENABLED)

/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcPrivateKey *privateKey, const uint8_t *digest, size_t digestLen,
   EcdsaSignature *signature)
{
   error_t error;
   ssp_err_t status;
   size_t n;
   size_t orderLen;
   size_t modLen;
   const EcCurve *curve;

   //Check parameters
   if(privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get elliptic curve parameters
   curve = privateKey->curve;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;

   //Check elliptic curve parameters
   if(modLen <= 24)
   {
      n = 24;
   }
   else if(modLen <= 28)
   {
      n = 28;
   }
   else if(modLen <= 32)
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

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s5d9CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.digest, 0, n);
   osMemcpy((uint8_t *) ecArgs.digest + n - digestLen, digest, digestLen);

   //Set domain parameters
   ecScalarExport(curve->a, n / 4, (uint8_t *) ecArgs.params, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->b, n / 4, (uint8_t *) ecArgs.params + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->p, n / 4, (uint8_t *) ecArgs.params + n * 2, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->q, n / 4, (uint8_t *) ecArgs.params + n * 3, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set base point
   ecScalarExport(curve->g.x, n / 4, (uint8_t *) ecArgs.g, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->g.y, n / 4, (uint8_t *) ecArgs.g + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set private key
   ecScalarExport(privateKey->d, n / 4, (uint8_t *) ecArgs.d, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Generate ECDSA signature
   if(n == 24)
   {
      status = HW_SCE_ECC_192GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else if(n == 28)
   {
      status = HW_SCE_ECC_224GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else if(n == 32)
   {
      status = HW_SCE_ECC_256GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else
   {
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == SSP_SUCCESS)
   {
      //Save elliptic curve parameters
      signature->curve = curve;

      //Copy integer R
      error = ecScalarImport(signature->r, EC_MAX_ORDER_SIZE,
         (uint8_t *) ecArgs.r, n, EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Check status code
      if(!error)
      {
         //Copy integer S
         error = ecScalarImport(signature->s, EC_MAX_ORDER_SIZE,
            (uint8_t *) ecArgs.s, n, EC_SCALAR_FORMAT_BIG_ENDIAN);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s5d9CryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief ECDSA signature verification
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaVerifySignature(const EcPublicKey *publicKey,
   const uint8_t *digest, size_t digestLen, const EcdsaSignature *signature)
{
   ssp_err_t status;
   size_t n;
   size_t orderLen;
   size_t modLen;
   const EcCurve *curve;

   //Check parameters
   if(publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(publicKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

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

   //Get elliptic curve parameters
   curve = publicKey->curve;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;

   //Check elliptic curve parameters
   if(modLen <= 24)
   {
      n = 24;
   }
   else if(modLen <= 28)
   {
      n = 28;
   }
   else if(modLen <= 32)
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

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Acquire exclusive access to the SCE7 module
   osAcquireMutex(&s5d9CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.digest, 0, n);
   osMemcpy((uint8_t *) ecArgs.digest + n - digestLen, digest, digestLen);

   //Set domain parameters
   ecScalarExport(curve->a, n / 4, (uint8_t *) ecArgs.params, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->b, n / 4, (uint8_t *) ecArgs.params + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->p, n / 4, (uint8_t *) ecArgs.params + n * 2, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->q, n / 4, (uint8_t *) ecArgs.params + n * 3, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set base point
   ecScalarExport(curve->g.x, n / 4, (uint8_t *) ecArgs.g, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(curve->g.y, n / 4, (uint8_t *) ecArgs.g + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set public key
   ecScalarExport(publicKey->q.x, n / 4, (uint8_t *) ecArgs.q, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(publicKey->q.y, n / 4, (uint8_t *) ecArgs.q + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set signature
   ecScalarExport(signature->r, n / 4, (uint8_t *) ecArgs.r, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(signature->s, n / 4, (uint8_t *) ecArgs.s, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Verify ECDSA signature
   if(n == 24)
   {
      status = HW_SCE_ECC_192VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else if(n == 28)
   {
      status = HW_SCE_ECC_224VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else if(n == 32)
   {
      status = HW_SCE_ECC_256VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.digest, ecArgs.r, ecArgs.s);
   }
   else
   {
      status = SSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Release exclusive access to the SCE7 module
   osReleaseMutex(&s5d9CryptoMutex);

   //Return status code
   return (status == SSP_SUCCESS) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
}

#endif
#endif
