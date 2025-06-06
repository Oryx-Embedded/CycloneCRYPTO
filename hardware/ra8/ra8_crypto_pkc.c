/**
 * @file ra8_crypto_pkc.c
 * @brief RA8 public-key hardware accelerator
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
#include "hw_sce_ra_private.h"
#include "hw_sce_rsa_private.h"
#include "hw_sce_ecc_private.h"
#include "core/crypto.h"
#include "hardware/ra8/ra8_crypto.h"
#include "hardware/ra8/ra8_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/ecdsa.h"
#include "debug.h"

//Check crypto library configuration
#if (RA8_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
static Ra8RsaArgs rsaArgs;
static Ra8EcArgs ecArgs;

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
   fsp_err_t status;
   size_t aLen;
   size_t eLen;
   size_t pLen;
   sce_oem_cmd_t command;

   //Get the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Get the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Get the length of the modulus, in bytes
   pLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if((aLen <= 128 && eLen <= 4 && pLen == 128) ||
      (aLen <= 256 && eLen <= 4 && pLen == 256) ||
      (aLen <= 384 && eLen <= 4 && pLen == 384) ||
      (aLen <= 512 && eLen <= 4 && pLen == 512))
   {
      //Select appropriate scalar length
      if(pLen == 128)
      {
         command = SCE_OEM_CMD_RSA1024_PUBLIC;
      }
      else if(pLen == 256)
      {
         command = SCE_OEM_CMD_RSA2048_PUBLIC;
      }
      else if(pLen == 384)
      {
         command = SCE_OEM_CMD_RSA3072_PUBLIC;
      }
      else
      {
         command = SCE_OEM_CMD_RSA4096_PUBLIC;
      }

      //Acquire exclusive access to the RSIP7 module
      osAcquireMutex(&ra8CryptoMutex);

      //Format message representative
      mpiWriteRaw(a, (uint8_t *) rsaArgs.m, pLen);

      //Format public key
      mpiWriteRaw(p, (uint8_t *) rsaArgs.key, pLen);
      mpiWriteRaw(e, (uint8_t *) rsaArgs.key + pLen, 4);

      //Install the plaintext public key and get the wrapped key
      status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
         command, NULL, NULL, (uint8_t *) rsaArgs.key, rsaArgs.wrappedKey);

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Perform RSA encryption
         if(pLen == 128)
         {
            status = HW_SCE_Rsa1024ModularExponentEncryptSub(rsaArgs.wrappedKey,
               rsaArgs.m, rsaArgs.c);
         }
         else if(pLen == 256)
         {
            status = HW_SCE_Rsa2048ModularExponentEncryptSub(rsaArgs.wrappedKey,
               rsaArgs.m, rsaArgs.c);
         }
         else if(pLen == 384)
         {
            status = HW_SCE_Rsa3072ModularExponentEncryptSub(rsaArgs.wrappedKey,
               rsaArgs.m, rsaArgs.c);
         }
         else if(pLen == 512)
         {
            status = HW_SCE_Rsa4096ModularExponentEncryptSub(rsaArgs.wrappedKey,
               rsaArgs.m, rsaArgs.c);
         }
         else
         {
            status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }
      }

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Copy the ciphertext representative
         error = mpiReadRaw(r, (uint8_t *) rsaArgs.c, pLen);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the RSIP7 module
      osReleaseMutex(&ra8CryptoMutex);
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
   fsp_err_t status;
   size_t aLen;
   size_t eLen;
   size_t pLen;
   sce_oem_cmd_t command;

   //Get the length of the integer, in bytes
   aLen = mpiGetByteLength(a);
   //Get the length of the exponent, in bytes
   eLen = mpiGetByteLength(e);
   //Get the length of the modulus, in bytes
   pLen = mpiGetByteLength(p);

   //The accelerator supports operand lengths up to 4096 bits
   if((aLen <= 128 && eLen <= 128 && pLen == 128) ||
      (aLen <= 256 && eLen <= 256 && pLen == 256) ||
      (aLen <= 384 && eLen <= 384 && pLen == 384) ||
      (aLen <= 512 && eLen <= 512 && pLen == 512))
   {
      //Select appropriate scalar length
      if(pLen == 128)
      {
         command = SCE_OEM_CMD_RSA1024_PRIVATE;
      }
      else if(pLen == 256)
      {
         command = SCE_OEM_CMD_RSA2048_PRIVATE;
      }
      else if(pLen == 384)
      {
         command = SCE_OEM_CMD_RSA3072_PRIVATE;
      }
      else
      {
         command = SCE_OEM_CMD_RSA4096_PRIVATE;
      }

      //Acquire exclusive access to the RSIP7 module
      osAcquireMutex(&ra8CryptoMutex);

      //Format ciphertext representative
      mpiWriteRaw(a, (uint8_t *) rsaArgs.c, pLen);

      //Format private key
      mpiWriteRaw(p, (uint8_t *) rsaArgs.key, pLen);
      mpiWriteRaw(e, (uint8_t *) rsaArgs.key + pLen, pLen);

      //Install the plaintext private key and get the wrapped key
      status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
         command, NULL, NULL, (uint8_t *) rsaArgs.key, rsaArgs.wrappedKey);

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Perform RSA decryption
         if(pLen == 128)
         {
            status = HW_SCE_Rsa1024ModularExponentDecryptSub(rsaArgs.wrappedKey,
               rsaArgs.c, rsaArgs.m);
         }
         else if(pLen == 256)
         {
            status = HW_SCE_Rsa2048ModularExponentDecryptSub(rsaArgs.wrappedKey,
               rsaArgs.c, rsaArgs.m);
         }
         else if(pLen == 384)
         {
            status = HW_SCE_Rsa3072ModularExponentDecryptSub(rsaArgs.wrappedKey,
               rsaArgs.c, rsaArgs.m);
         }
         else if(pLen == 512)
         {
            status = HW_SCE_Rsa4096ModularExponentDecryptSub(rsaArgs.wrappedKey,
               rsaArgs.c, rsaArgs.m);
         }
         else
         {
            status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }
      }

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Copy the message representative
         error = mpiReadRaw(r, (uint8_t *) rsaArgs.m, pLen);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the RSIP7 module
      osReleaseMutex(&ra8CryptoMutex);
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
   if((nLen == 128 && dLen <= 128) || (nLen == 384 && dLen <= 384))
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
   fsp_err_t status;
   size_t n;
   size_t offset;
   size_t modLen;
   size_t orderLen;
   uint32_t curveType;
   uint32_t command;
   sce_oem_cmd_t oemCommand;
   const uint32_t *domainParams;

   //Get the length of the modulus, in words
   modLen = (curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   orderLen = (curve->orderSize + 31) / 32;

   //Determine the length of the operands, in bytes
   n = (curve->fieldSize + 7) / 8;
   n = (n + 15U) & ~15U;

   //Check elliptic curve parameters
   if(osStrcmp(curve->name, "secp256k1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_KOBLITZ;
      oemCommand = SCE_OEM_CMD_ECC_SECP256K1_PRIVATE;
      domainParams = DomainParam_Koblitz_secp256k1;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P256_PRIVATE;
      domainParams = DomainParam_NIST_P256;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "secp384r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P384_PRIVATE;
      domainParams = DomainParam_NIST_P384;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "secp521r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P521_PRIVATE;
      domainParams = DomainParam_NIST_P521;
      command = 0;
      offset = 12;
   }
   else if(osStrcmp(curve->name, "brainpoolP256r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P256R1_PRIVATE;
      domainParams = DomainParam_Brainpool_256r1;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "brainpoolP384r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P384R1_PRIVATE;
      domainParams = DomainParam_Brainpool_384r1;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "brainpoolP512r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P512R1_PRIVATE;
      domainParams = DomainParam_Brainpool_512r1;
      command = 0;
      offset = 0;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Acquire exclusive access to the RSIP7 module
   osAcquireMutex(&ra8CryptoMutex);

   //Set scalar value
   ecScalarExport(d, orderLen, (uint8_t *) ecArgs.d, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set input point
   ecScalarExport(s->x, modLen, (uint8_t *) ecArgs.g, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(s->y, modLen, (uint8_t *) ecArgs.g + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Install the plaintext private key and get the wrapped key
   status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
      oemCommand, NULL, NULL, (uint8_t *) ecArgs.d, ecArgs.wrappedKey);

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Perform scalar multiplication
      if(curve->fieldSize == 256)
      {
         status = HW_SCE_Ecc256ScalarMultiplicationSub(&curveType,
            &command, ecArgs.wrappedKey, ecArgs.g, domainParams, ecArgs.q);
      }
      else if(curve->fieldSize == 384)
      {
         status = HW_SCE_Ecc384ScalarMultiplicationSub(&curveType,
            ecArgs.wrappedKey, ecArgs.g, domainParams, ecArgs.q);
      }
      else if(curve->fieldSize == 512)
      {
         status = HW_SCE_Ecc512ScalarMultiplicationSub(ecArgs.wrappedKey,
            ecArgs.g, domainParams, ecArgs.q);
      }
      else if(curve->fieldSize == 521)
      {
         status = HW_SCE_Ecc521ScalarMultiplicationSub(ecArgs.wrappedKey,
            ecArgs.g, domainParams, ecArgs.q);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the x-coordinate of the result
      error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE,
         (uint8_t *) ecArgs.q + offset, modLen * 4,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE,
            (uint8_t *) ecArgs.q + offset + n, modLen * 4,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
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

   //Release exclusive access to the RSIP7 module
   osReleaseMutex(&ra8CryptoMutex);

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
   fsp_err_t status;
   size_t n;
   size_t offset;
   size_t orderLen;
   uint32_t curveType;
   uint32_t command;
   sce_oem_cmd_t oemCommand;
   const uint32_t *domainParams;
   const EcCurve *curve;

   //Check parameters
   if(privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get elliptic curve parameters
   curve = privateKey->curve;

   //Get the length of the order, in words
   orderLen = (curve->orderSize + 31) / 32;

   //Determine the length of the operands, in bytes
   n = (curve->fieldSize + 7) / 8;
   n = (n + 15U) & ~15U;

   //Check elliptic curve parameters
   if(osStrcmp(curve->name, "secp256k1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_KOBLITZ;
      oemCommand = SCE_OEM_CMD_ECC_SECP256K1_PRIVATE;
      domainParams = DomainParam_Koblitz_secp256k1;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P256_PRIVATE;
      domainParams = DomainParam_NIST_P256;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "secp384r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P384_PRIVATE;
      domainParams = DomainParam_NIST_P384;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "secp521r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P521_PRIVATE;
      domainParams = DomainParam_NIST_P521;
      command = 0;
      offset = 12;
   }
   else if(osStrcmp(curve->name, "brainpoolP256r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P256R1_PRIVATE;
      domainParams = DomainParam_Brainpool_256r1;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "brainpoolP384r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P384R1_PRIVATE;
      domainParams = DomainParam_Brainpool_384r1;
      command = 0;
      offset = 0;
   }
   else if(osStrcmp(curve->name, "brainpoolP512r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P512R1_PRIVATE;
      domainParams = DomainParam_Brainpool_512r1;
      command = 0;
      offset = 0;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, (curve->orderSize + 7) / 8);

   //Acquire exclusive access to the RSIP7 module
   osAcquireMutex(&ra8CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.digest, 0, n);
   osMemcpy((uint8_t *) ecArgs.digest + n - digestLen, digest, digestLen);

   //Set private key
   ecScalarExport(privateKey->d, orderLen, (uint8_t *) ecArgs.d, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Install the plaintext private key and get the wrapped key
   status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
      oemCommand, NULL, NULL, (uint8_t *) ecArgs.d, ecArgs.wrappedKey);

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Generate ECDSA signature
      if(curve->fieldSize == 256)
      {
         status = HW_SCE_EcdsaSignatureGenerateSub(&curveType, &command,
            ecArgs.wrappedKey, ecArgs.digest, domainParams, ecArgs.signature);
      }
      else if(curve->fieldSize == 384)
      {
         status = HW_SCE_EcdsaP384SignatureGenerateSub(&curveType,
            ecArgs.wrappedKey, ecArgs.digest, domainParams, ecArgs.signature);
      }
      else if(curve->fieldSize == 512)
      {
         status = HW_SCE_EcdsaP512SignatureGenerateSub(ecArgs.wrappedKey,
            ecArgs.digest, domainParams, ecArgs.signature);
      }
      else if(curve->fieldSize == 521)
      {
         status = HW_SCE_EcdsaP521SignatureGenerateSub(ecArgs.wrappedKey,
            ecArgs.digest, domainParams, ecArgs.signature);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Save elliptic curve parameters
      signature->curve = curve;

      //Copy integer R
      error = ecScalarImport(signature->r, EC_MAX_ORDER_SIZE,
         (uint8_t *) ecArgs.signature + offset, orderLen * 4,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Check status code
      if(!error)
      {
         //Copy integer S
         error = ecScalarImport(signature->s, EC_MAX_ORDER_SIZE,
            (uint8_t *) ecArgs.signature + offset + n, orderLen * 4,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the RSIP7 module
   osReleaseMutex(&ra8CryptoMutex);

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
   fsp_err_t status;
   size_t n;
   size_t modLen;
   size_t orderLen;
   uint32_t curveType;
   uint32_t command;
   sce_oem_cmd_t oemCommand;
   const uint32_t *domainParams;
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

   //Get the length of the modulus, in words
   modLen = (curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   orderLen = (curve->orderSize + 31) / 32;

   //Determine the length of the operands, in bytes
   n = (curve->fieldSize + 7) / 8;
   n = (n + 15U) & ~15U;

   //Check elliptic curve parameters
   if(osStrcmp(curve->name, "secp256k1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_KOBLITZ;
      oemCommand = SCE_OEM_CMD_ECC_SECP256K1_PUBLIC;
      domainParams = DomainParam_Koblitz_secp256k1;
      command = 0;
   }
   else if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P256_PUBLIC;
      domainParams = DomainParam_NIST_P256;
      command = 0;
   }
   else if(osStrcmp(curve->name, "secp384r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P384_PUBLIC;
      domainParams = DomainParam_NIST_P384;
      command = 0;
   }
   else if(osStrcmp(curve->name, "secp521r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P521_PUBLIC;
      domainParams = DomainParam_NIST_P521;
      command = 0;
   }
   else if(osStrcmp(curve->name, "brainpoolP256r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P256R1_PUBLIC;
      domainParams = DomainParam_Brainpool_256r1;
      command = 0;
   }
   else if(osStrcmp(curve->name, "brainpoolP384r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P384R1_PUBLIC;
      domainParams = DomainParam_Brainpool_384r1;
      command = 0;
   }
   else if(osStrcmp(curve->name, "brainpoolP512r1") == 0)
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P512R1_PUBLIC;
      domainParams = DomainParam_Brainpool_512r1;
      command = 0;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, (curve->orderSize + 7) / 8);

   //Acquire exclusive access to the RSIP7 module
   osAcquireMutex(&ra8CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.digest, 0, n);
   osMemcpy((uint8_t *) ecArgs.digest + n - digestLen, digest, digestLen);

   //Set public key
   ecScalarExport(publicKey->q.x, modLen, (uint8_t *) ecArgs.q, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(publicKey->q.y, modLen, (uint8_t *) ecArgs.q + n, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Set signature
   ecScalarExport(signature->r, orderLen, (uint8_t *) ecArgs.signature, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   ecScalarExport(signature->s, orderLen, (uint8_t *) ecArgs.signature + n,
      n, EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Install the plaintext public key and get the wrapped key
   status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
      oemCommand, NULL, NULL, (uint8_t *) ecArgs.q, ecArgs.wrappedKey);

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Verify ECDSA signature
      if(curve->fieldSize == 256)
      {
         status = HW_SCE_EcdsaSignatureVerificationSub(&curveType, &command,
            ecArgs.wrappedKey, ecArgs.digest, ecArgs.signature, domainParams);
      }
      else if(curve->fieldSize == 384)
      {
         status = HW_SCE_EcdsaP384SignatureVerificationSub(&curveType,
            ecArgs.wrappedKey, ecArgs.digest, ecArgs.signature, domainParams);
      }
      else if(curve->fieldSize == 512)
      {
         status = HW_SCE_EcdsaP512SignatureVerificationSub(ecArgs.wrappedKey,
            ecArgs.digest, ecArgs.signature, domainParams);
      }
      else if(curve->fieldSize == 521)
      {
         status = HW_SCE_EcdsaP521SignatureVerificationSub(ecArgs.wrappedKey,
            ecArgs.digest, ecArgs.signature, domainParams);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }

   //Release exclusive access to the RSIP7 module
   osReleaseMutex(&ra8CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
}

#endif
#endif
