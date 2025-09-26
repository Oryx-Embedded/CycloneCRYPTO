/**
 * @file mcxn947_crypto_pkc.c
 * @brief NXP MCX N947 public-key hardware accelerator (PKA)
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
 * @version 2.5.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include <mcuxClToolchain.h>
#include <mcuxClEls.h>
#include <mcuxClEcc.h>
#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include "core/crypto.h"
#include "hardware/mcxn947/mcxn947_crypto.h"
#include "hardware/mcxn947/mcxn947_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/ecdsa.h"
#include "ecc/x25519.h"
#include "ecc/x448.h"
#include "ecc/ed25519.h"
#include "debug.h"

//Check crypto library configuration
#if (MCXN947_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
ALIGNED ElsRsaArgs elsRsaArgs;
ALIGNED ElsEccArgs elsEccArgs;
ALIGNED ElsEcdsaArgs elsEcdsaArgs;
ALIGNED ElsMontDhArgs elsMontDhArgs;
ALIGNED ElsEddsaArgs elsEddsaArgs;

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (secp192r1)
static const uint8_t SECP192R1_PRECG[] =
{
   0x51, 0xA5, 0x81, 0xD9, 0x18, 0x4A, 0xC7, 0x37, 0x47, 0x30, 0xD4, 0xF4, 0x80, 0xD1, 0x09, 0x0B,
   0xB1, 0x99, 0x63, 0xD8, 0xC0, 0xA1, 0xE3, 0x40,
   0x5B, 0xD8, 0x1E, 0xE2, 0xE0, 0xBB, 0x9F, 0x6E, 0x7C, 0xDF, 0xCE, 0xA0, 0x2F, 0x68, 0x3F, 0x16,
   0xEC, 0xC5, 0x67, 0x31, 0xE6, 0x99, 0x12, 0xA5
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (secp224r1)
static const uint8_t SECP224R1_PRECG[] =
{
   0x04, 0x99, 0xAA, 0x8A, 0x5F, 0x8E, 0xBE, 0xEF, 0xEC, 0x27, 0xA4, 0xE1, 0x3A, 0x0B, 0x91, 0xFB,
   0x29, 0x91, 0xFA, 0xB0, 0xA0, 0x06, 0x41, 0x96, 0x6C, 0xAB, 0x26, 0xE3,
   0x69, 0x16, 0xF6, 0xD4, 0x33, 0x8C, 0x5B, 0x81, 0xD7, 0x7A, 0xAE, 0x82, 0xF7, 0x06, 0x84, 0xD9,
   0x29, 0x61, 0x0D, 0x54, 0x50, 0x75, 0x10, 0x40, 0x77, 0x66, 0xAF, 0x5D
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (secp256k1)
static const uint8_t SECP256K1_PRECG[] =
{
   0x8F, 0x68, 0xB9, 0xD2, 0xF6, 0x3B, 0x5F, 0x33, 0x92, 0x39, 0xC1, 0xAD, 0x98, 0x1F, 0x16, 0x2E,
   0xE8, 0x8C, 0x56, 0x78, 0x72, 0x3E, 0xA3, 0x35, 0x1B, 0x7B, 0x44, 0x4C, 0x9E, 0xC4, 0xC0, 0xDA,
   0x66, 0x2A, 0x9F, 0x2D, 0xBA, 0x06, 0x39, 0x86, 0xDE, 0x1D, 0x90, 0xC2, 0xB6, 0xBE, 0x21, 0x5D,
   0xBB, 0xEA, 0x2C, 0xFE, 0x95, 0x51, 0x0B, 0xFD, 0xF2, 0x3C, 0xBF, 0x79, 0x50, 0x1F, 0xFF, 0x82
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (secp256r1)
static const uint8_t SECP256R1_PRECG[] =
{
   0x44, 0x7D, 0x73, 0x9B, 0xEE, 0xDB, 0x5E, 0x67, 0xFB, 0x98, 0x2F, 0xD5, 0x88, 0xC6, 0x76, 0x6E,
   0xFC, 0x35, 0xFF, 0x7D, 0xC2, 0x97, 0xEA, 0xC3, 0x57, 0xC8, 0x4F, 0xC9, 0xD7, 0x89, 0xBD, 0x85,
   0x2D, 0x48, 0x25, 0xAB, 0x83, 0x41, 0x31, 0xEE, 0xE1, 0x2E, 0x9D, 0x95, 0x3A, 0x4A, 0xAF, 0xF7,
   0x3D, 0x34, 0x9B, 0x95, 0xA7, 0xFA, 0xE5, 0x00, 0x0C, 0x7E, 0x33, 0xC9, 0x72, 0xE2, 0x5B, 0x32
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (secp384r1)
static const uint8_t SECP384R1_PRECG[] =
{
   0xC1, 0x9E, 0x0B, 0x4C, 0x80, 0x01, 0x19, 0xC4, 0x40, 0xF7, 0xF9, 0xE7, 0x06, 0x42, 0x12, 0x79,
   0xB4, 0x2A, 0x31, 0xAF, 0x8A, 0x3E, 0x29, 0x7D, 0xDB, 0x29, 0x87, 0x89, 0x4D, 0x10, 0xDD, 0xEA,
   0xBA, 0x06, 0x54, 0x58, 0xA4, 0xF5, 0x2D, 0x78, 0xA6, 0x28, 0xB0, 0x9A, 0xAA, 0x03, 0xBD, 0x53,
   0x16, 0xF3, 0xFD, 0xBF, 0x03, 0x56, 0xB3, 0x01, 0xE5, 0xA0, 0x19, 0x1D, 0x1F, 0x5B, 0x77, 0xF6,
   0x57, 0x7A, 0x30, 0xEA, 0xE3, 0x56, 0x7A, 0xF9, 0xC1, 0xC7, 0xCA, 0xD1, 0x35, 0xF6, 0xEB, 0xF2,
   0xAF, 0x68, 0xAA, 0x6D, 0xE6, 0x39, 0xD8, 0x58, 0x82, 0x2D, 0x0F, 0xC5, 0xE6, 0xC8, 0x8C, 0x41
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (secp521r1)
static const uint8_t SECP521R1_PRECG[] =
{
   0x00, 0x8E, 0x81, 0x8D, 0x28, 0xF3, 0x81, 0xD8, 0xB2, 0x05, 0xED, 0xFF, 0x69, 0x61, 0x3B, 0x96,
   0x2E, 0x0C, 0x77, 0xD2, 0x23, 0xEF, 0x25, 0xCC, 0x1C, 0x99, 0xD9, 0xA6, 0x2E, 0x4F, 0x25, 0x72,
   0xC1, 0x61, 0x7A, 0xD0, 0xF5, 0xE9, 0xA8, 0x6B, 0x71, 0x04, 0xE8, 0x97, 0x00, 0xD4, 0xDA, 0x71,
   0x3C, 0xB4, 0x08, 0xF3, 0xDE, 0x44, 0x65, 0xF8, 0x6A, 0xC4, 0xEE, 0x31, 0xE7, 0x1A, 0x28, 0x64,
   0x92, 0xAD,
   0x01, 0x3E, 0xFD, 0xBC, 0x85, 0x6E, 0x8F, 0x68, 0xBF, 0x44, 0xD4, 0xE1, 0x9F, 0xC7, 0xC3, 0x26,
   0xFE, 0x48, 0xA1, 0x6F, 0x78, 0x55, 0xC8, 0x08, 0x66, 0x23, 0x71, 0x96, 0xBF, 0x8F, 0x72, 0xEA,
   0x0D, 0xCB, 0x42, 0x22, 0x85, 0xDC, 0x03, 0x70, 0x68, 0x9F, 0xBE, 0x72, 0x6F, 0x8C, 0xE0, 0x45,
   0xA4, 0x03, 0x8B, 0x64, 0x0F, 0x2B, 0x67, 0x17, 0x76, 0x0F, 0x72, 0x12, 0x31, 0xCF, 0x8C, 0xDF,
   0x1F, 0x60
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (brainpoolP256r1)
static const uint8_t BRAINPOOLP256R1_PRECG[] =
{
   0x4A, 0x14, 0xC0, 0x30, 0x3B, 0x85, 0x6C, 0x94, 0xB4, 0x43, 0x85, 0x11, 0x7F, 0x87, 0xED, 0x9D,
   0x12, 0x00, 0xCA, 0x9B, 0x11, 0x00, 0x65, 0x90, 0xEB, 0x6B, 0x65, 0x1C, 0xF5, 0x84, 0x72, 0xC9,
   0x7B, 0x81, 0xE4, 0x70, 0xDA, 0xE2, 0xD5, 0xEF, 0xE6, 0x38, 0x73, 0x49, 0x8B, 0x47, 0xCC, 0x5E,
   0xD5, 0x44, 0xA0, 0x68, 0xCD, 0x73, 0x21, 0x17, 0x52, 0x9C, 0x5C, 0xD6, 0x28, 0xF8, 0x52, 0xD1
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (brainpoolP384r1)
static const uint8_t BRAINPOOLP384R1_PRECG[] =
{
   0x23, 0x69, 0xDB, 0xB6, 0x39, 0x7C, 0x99, 0xF1, 0x89, 0x74, 0xB5, 0x68, 0x8E, 0x81, 0xAF, 0x98,
   0xDF, 0x4D, 0xDA, 0xCC, 0xBB, 0x1F, 0xDC, 0x04, 0xE1, 0x8A, 0x5D, 0x2D, 0x02, 0xC7, 0xF7, 0x27,
   0x02, 0xA3, 0x53, 0xBC, 0x53, 0x45, 0xA9, 0x46, 0x6B, 0xF5, 0x50, 0xB0, 0x4D, 0x99, 0x4B, 0x04,
   0x6F, 0x47, 0xB1, 0x1D, 0xAA, 0x3B, 0x12, 0x4F, 0x93, 0xB0, 0x87, 0x75, 0x92, 0x5F, 0xF0, 0xA8,
   0x12, 0x73, 0x68, 0xF1, 0x07, 0x42, 0xFA, 0x8F, 0xCD, 0x41, 0xCA, 0xE9, 0x33, 0x34, 0xCE, 0x66,
   0x43, 0xF1, 0x43, 0xE6, 0x50, 0x0C, 0xB2, 0xC1, 0x0E, 0xE1, 0x88, 0xBB, 0x14, 0x50, 0x4C, 0x85
};

//Pre-computed value of (2 ^ (byteLenN * 4)) * G (brainpoolP512r1)
static const uint8_t BRAINPOOLP512R1_PRECG[] =
{
   0x7B, 0x59, 0x13, 0xF7, 0x66, 0xC4, 0xED, 0x95, 0xD5, 0x26, 0x2C, 0xE1, 0xB8, 0xF1, 0xB2, 0xAF,
   0xC0, 0x56, 0xFD, 0x65, 0x8F, 0x28, 0x48, 0x70, 0x79, 0xA8, 0x3D, 0x9B, 0x94, 0x5E, 0x84, 0x60,
   0x1B, 0xAE, 0x0F, 0x47, 0xAC, 0xA3, 0xB9, 0x4E, 0x97, 0x50, 0x2F, 0x33, 0x73, 0x0A, 0x37, 0x21,
   0x9D, 0x18, 0x9C, 0x54, 0x08, 0xAC, 0x7D, 0xA5, 0xCA, 0x44, 0x81, 0x27, 0xEF, 0x66, 0xEF, 0xB5,
   0x3B, 0x4D, 0x8E, 0x45, 0x4F, 0xFC, 0x59, 0x3A, 0x37, 0x27, 0xEA, 0x1E, 0xEA, 0x20, 0xB7, 0x08,
   0xC2, 0x1F, 0xCA, 0x91, 0x61, 0x30, 0x6A, 0xF0, 0xE4, 0x66, 0x56, 0xA7, 0x5F, 0xC4, 0x50, 0xA8,
   0xFB, 0x4E, 0xDB, 0x0D, 0xBC, 0x57, 0x88, 0x77, 0x24, 0xEC, 0x6F, 0x84, 0x4E, 0xB4, 0x96, 0xC3,
   0x3E, 0x94, 0x70, 0xF8, 0xDA, 0x00, 0x92, 0xC9, 0xD6, 0x10, 0x45, 0x3C, 0xC2, 0xF4, 0x58, 0x72
};


#if (MPI_SUPPORT == ENABLED)

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
   uint_t aLen;
   uint_t eLen;
   uint_t pLen;
   mcuxClRsa_KeyEntry_t ee;
   mcuxClRsa_KeyEntry_t pp;
   mcuxClRsa_Key privateKey;

   //Initialize status code
   error = NO_ERROR;

   //Get the length of the operands, in bytes
   aLen = mpiGetByteLength(a);
   eLen = mpiGetByteLength(e);
   pLen = mpiGetByteLength(p);

   //Check the length of the operands
   if(aLen <= pLen && eLen <= 512 && pLen <= 512)
   {
      //Acquire exclusive access to the ELS module
      osAcquireMutex(&mcxn947CryptoMutex);

      //Copy the input integer
      mpiWriteRaw(a, elsRsaArgs.c, pLen);
      //Copy the public exponent
      mpiWriteRaw(e, elsRsaArgs.e, eLen);
      //Copy the modulus
      mpiWriteRaw(p, elsRsaArgs.n, pLen);

      //Set the public exponent
      ee.pKeyEntryData = elsRsaArgs.e;
      ee.keyEntryLength = eLen;

      //Set the modulus
      pp.pKeyEntryData = elsRsaArgs.n;
      pp.keyEntryLength = pLen;

      //Set the RSA private key
      privateKey.keytype = MCUXCLRSA_KEY_PRIVATEPLAIN;
      privateKey.pMod1 = &pp;
      privateKey.pMod2 = NULL;
      privateKey.pQInv = NULL;
      privateKey.pExp1 = &ee;
      privateKey.pExp2 = NULL;
      privateKey.pExp3 = NULL;

      //Apply RSAVP1 primitive
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClRsa_sign(
         &elsSession, &privateKey, elsRsaArgs.c, pLen,
         (mcuxClRsa_SignVerifyMode_t *) &mcuxClRsa_Mode_Sign_NoEncode,
         0, 0, elsRsaArgs.m));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) ||
         status != MCUXCLRSA_STATUS_SIGN_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();

      //Check status code
      if(!error)
      {
         //Copy the output
         error = mpiReadRaw(r, elsRsaArgs.m, pLen);
      }

      //Release exclusive access to the ELS module
      osReleaseMutex(&mcxn947CryptoMutex);
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
   mcuxClRsa_KeyEntry_t n;
   mcuxClRsa_KeyEntry_t e;
   mcuxClRsa_Key publicKey;

   //The message representative m shall be between 0 and n - 1
   if(mpiCompInt(m, 0) < 0 || mpiComp(m, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Initialize status code
   error = NO_ERROR;

   //Get the length of the modulus, in bytes
   nLen = mpiGetByteLength(&key->n);
   //Get the length of the public exponent, in bytes
   eLen = mpiGetByteLength(&key->e);

   //Check the length of the operands
   if(nLen <= 512 && eLen <= 512)
   {
      //Acquire exclusive access to the ELS module
      osAcquireMutex(&mcxn947CryptoMutex);

      //Copy the modulus
      mpiWriteRaw(&key->n, elsRsaArgs.n, nLen);
      //Copy the public exponent
      mpiWriteRaw(&key->e, elsRsaArgs.e, eLen);

      //Set the modulus
      n.pKeyEntryData = elsRsaArgs.n;
      n.keyEntryLength = nLen;

      //Set the public exponent
      e.pKeyEntryData = elsRsaArgs.e;
      e.keyEntryLength = eLen;

      //Set the RSA public key
      publicKey.keytype = MCUXCLRSA_KEY_PUBLIC;
      publicKey.pMod1 = &n;
      publicKey.pMod2 = NULL;
      publicKey.pQInv = NULL;
      publicKey.pExp1 = &e;
      publicKey.pExp2 = NULL;
      publicKey.pExp3 = NULL;

      //Copy the message representative
      mpiWriteRaw(m, elsRsaArgs.m, nLen);

      //Apply RSASP1 primitive
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClRsa_verify(
         &elsSession, &publicKey, NULL, 0, elsRsaArgs.m,
         (mcuxClRsa_SignVerifyMode_t *) &mcuxClRsa_Mode_Verify_NoVerify,
         0, 0, elsRsaArgs.c));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_verify) ||
         status != MCUXCLRSA_STATUS_VERIFYPRIMITIVE_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();

      //Check status code
      if(!error)
      {
         //Copy the ciphertext representative
         error = mpiReadRaw(c, elsRsaArgs.c, nLen);
      }

      //Release exclusive access to the ELS module
      osReleaseMutex(&mcxn947CryptoMutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LENGTH;
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
   mcuxClRsa_KeyEntry_t n;
   mcuxClRsa_KeyEntry_t d;
   mcuxClRsa_KeyEntry_t p;
   mcuxClRsa_KeyEntry_t q;
   mcuxClRsa_KeyEntry_t dp;
   mcuxClRsa_KeyEntry_t dq;
   mcuxClRsa_KeyEntry_t qinv;
   mcuxClRsa_Key privateKey;

   //The ciphertext representative c shall be between 0 and n - 1
   if(mpiCompInt(c, 0) < 0 || mpiComp(c, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Initialize status code
   error = NO_ERROR;

   //Get the length of the modulus, in bytes
   nLen = mpiGetByteLength(&key->n);
   //Get the length of the private exponent, in bytes
   dLen = mpiGetByteLength(&key->d);

   //Check the length of the operands
   if(nLen <= 512 && dLen <= 512)
   {
      //Acquire exclusive access to the ELS module
      osAcquireMutex(&mcxn947CryptoMutex);

      //Use the Chinese remainder algorithm?
      if(mpiGetLength(&key->p) > 0 && mpiGetLength(&key->q) > 0 &&
         mpiGetLength(&key->dp) > 0 && mpiGetLength(&key->dq) > 0 &&
         mpiGetLength(&key->qinv) > 0)
      {
         //Copy the first factor
         mpiWriteRaw(&key->p, elsRsaArgs.p, nLen / 2);
         //Copy the second factor
         mpiWriteRaw(&key->q, elsRsaArgs.q, nLen / 2);
         //Copy the first factor's CRT exponent
         mpiWriteRaw(&key->dp, elsRsaArgs.dp, nLen / 2);
         //Copy the second factor's CRT exponent
         mpiWriteRaw(&key->dq, elsRsaArgs.dq, nLen / 2);
         //Copy the CRT coefficient
         mpiWriteRaw(&key->qinv, elsRsaArgs.qinv, nLen / 2);

         //Set the first factor
         p.pKeyEntryData = elsRsaArgs.p;
         p.keyEntryLength = nLen / 2;

         //Set the second factor
         q.pKeyEntryData = elsRsaArgs.q;
         q.keyEntryLength = nLen / 2;

         //Set the first factor's CRT exponent
         dp.pKeyEntryData = elsRsaArgs.dp;
         dp.keyEntryLength = nLen / 2;

         //Set the second factor's CRT exponent
         dq.pKeyEntryData = elsRsaArgs.dq;
         dq.keyEntryLength = nLen / 2;

         //Set the CRT coefficient
         qinv.pKeyEntryData = elsRsaArgs.qinv;
         qinv.keyEntryLength = nLen / 2;

         //Set the RSA private key
         privateKey.keytype = MCUXCLRSA_KEY_PRIVATECRT;
         privateKey.pMod1 = &p;
         privateKey.pMod2 = &q;
         privateKey.pQInv = &qinv;
         privateKey.pExp1 = &dp;
         privateKey.pExp2 = &dq;
         privateKey.pExp3 = NULL;
      }
      else
      {
         //Copy the modulus
         mpiWriteRaw(&key->n, elsRsaArgs.n, nLen);
         //Copy the private exponent
         mpiWriteRaw(&key->d, elsRsaArgs.d, dLen);

         //Set the modulus
         n.pKeyEntryData = elsRsaArgs.n;
         n.keyEntryLength = nLen;

         //Set the private exponent
         d.pKeyEntryData = elsRsaArgs.d;
         d.keyEntryLength = dLen;

         //Set the RSA private key
         privateKey.keytype = MCUXCLRSA_KEY_PRIVATEPLAIN;
         privateKey.pMod1 = &n;
         privateKey.pMod2 = NULL;
         privateKey.pQInv = NULL;
         privateKey.pExp1 = &d;
         privateKey.pExp2 = NULL;
         privateKey.pExp3 = NULL;
      }

      //Copy the ciphertext representative
      mpiWriteRaw(c, elsRsaArgs.c, nLen);

      //Apply RSAVP1 primitive
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClRsa_sign(
         &elsSession, &privateKey, elsRsaArgs.c, nLen,
         (mcuxClRsa_SignVerifyMode_t *) &mcuxClRsa_Mode_Sign_NoEncode,
         0, 0, elsRsaArgs.m));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) ||
         status != MCUXCLRSA_STATUS_SIGN_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();

      //Check status code
      if(!error)
      {
         //Copy the message representative
         error = mpiReadRaw(m, elsRsaArgs.m, nLen);
      }

      //Release exclusive access to the ELS module
      osReleaseMutex(&mcxn947CryptoMutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LENGTH;
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
   size_t modLen;
   size_t orderLen;
   mcuxClEcc_PointMult_Param_t pointMultParam;

   //Initialize status code
   error = NO_ERROR;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;

   //Check the length of the operands
   if(modLen <= 66 && orderLen <= 66)
   {
      //Acquire exclusive access to the ELS module
      osAcquireMutex(&mcxn947CryptoMutex);

      //Copy domain parameters
      ecScalarExport(curve->p, (modLen + 3) / 4, elsEccArgs.p, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->a, (modLen + 3) / 4, elsEccArgs.a, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->b, (modLen + 3) / 4, elsEccArgs.b, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->g.x, (modLen + 3) / 4, elsEccArgs.g, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->g.y, (modLen + 3) / 4, elsEccArgs.g + modLen,
         modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->q, (modLen + 3) / 4, elsEccArgs.q, orderLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Copy scalar
      ecScalarExport(d, (orderLen + 3) / 4, elsEccArgs.d, orderLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Copy input point
      ecScalarExport(s->x, (modLen + 3) / 4, elsEccArgs.input, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(s->y, (modLen + 3) / 4, elsEccArgs.input + modLen,
         modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Set point multiplication parameters
      pointMultParam.curveParam.pA = elsEccArgs.a;
      pointMultParam.curveParam.pB = elsEccArgs.b;
      pointMultParam.curveParam.pP = elsEccArgs.p;
      pointMultParam.curveParam.pG = elsEccArgs.g;
      pointMultParam.curveParam.pN = elsEccArgs.q;
      pointMultParam.curveParam.misc = (orderLen << 8) | modLen;
      pointMultParam.pScalar = elsEccArgs.d;
      pointMultParam.pPoint = elsEccArgs.input;
      pointMultParam.pResult = elsEccArgs.output;
      pointMultParam.optLen = 0;

      //Perform scalar multiplication
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEcc_PointMult(
         &elsSession, &pointMultParam));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) ||
         status != MCUXCLECC_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();

      //Check status code
      if(!error)
      {
         //Copy the x-coordinate of the result
         error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE, elsEccArgs.output,
            modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Copy the y-coordinate of the result
            error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE, elsEccArgs.output +
               modLen, modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Set the z-coordinate of the result
            ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);
         }
      }

      //Release exclusive access to the ELS module
      osReleaseMutex(&mcxn947CryptoMutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LENGTH;
   }

   //Return status code
   return error;
}


/**
 * @brief Twin multiplication
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d0.S + d1.T
 * @param[in] d0 An integer d such as 0 <= d0 < p
 * @param[in] s EC point
 * @param[in] d1 An integer d such as 0 <= d1 < p
 * @param[in] t EC point
 * @return Error code
 **/

error_t ecTwinMul(const EcCurve *curve, EcPoint3 *r, const uint32_t *d0,
   const EcPoint3 *s, const uint32_t *d1, const EcPoint3 *t)
{
   error_t error;
   EcPoint3 u;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   EcState *state;
#else
   EcState state[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(EcState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(EcState));
   //Save elliptic curve parameters
   state->curve = curve;

   //Compute d0.S
   error = ecMulFast(curve, r, d0, s);

   //Check status code
   if(!error)
   {
      //Compute d1.T
      error = ecMulFast(curve, &u, d1, t);
   }

   //Check status code
   if(!error)
   {
      //Compute d0.S + d1.T
      ecFullAdd(state, r, r, &u);
   }

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
   size_t modLen;
   size_t orderLen;
   const EcCurve *curve;
   mcuxClEcc_Sign_Param_t signParam;

   //Check parameters
   if(privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Initialize status code
   error = NO_ERROR;

   //Get elliptic curve parameters
   curve = privateKey->curve;

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;

   //Check the length of the operands
   if(modLen <= 66 && orderLen <= 66)
   {
      //Acquire exclusive access to the ELS module
      osAcquireMutex(&mcxn947CryptoMutex);

      //Copy domain parameters
      ecScalarExport(curve->p, (modLen + 3) / 4, elsEcdsaArgs.p, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->a, (modLen + 3) / 4, elsEcdsaArgs.a, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->b, (modLen + 3) / 4, elsEcdsaArgs.b, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->g.x, (modLen + 3) / 4, elsEcdsaArgs.g, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->g.y, (modLen + 3) / 4, elsEcdsaArgs.g + modLen,
         modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->q, (modLen + 3) / 4, elsEcdsaArgs.q, orderLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Copy private key
      ecScalarExport(privateKey->d, (orderLen + 3) / 4, elsEcdsaArgs.privateKey,
         orderLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Set point multiplication parameters
      signParam.curveParam.pA = elsEcdsaArgs.a;
      signParam.curveParam.pB = elsEcdsaArgs.b;
      signParam.curveParam.pP = elsEcdsaArgs.p;
      signParam.curveParam.pG = elsEcdsaArgs.g;
      signParam.curveParam.pN = elsEcdsaArgs.q;
      signParam.curveParam.misc = (orderLen << 8) | modLen;
      signParam.pHash = digest;
      signParam.pPrivateKey = elsEcdsaArgs.privateKey;
      signParam.pSignature = elsEcdsaArgs.signature;
      signParam.optLen = mcuxClEcc_Sign_Param_optLen_Pack(digestLen);
      signParam.pMode = &mcuxClEcc_ECDSA_ProtocolDescriptor;

      //Generate ECDSA signature
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEcc_Sign(
         &elsSession, &signParam));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Sign) ||
         status != MCUXCLECC_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();

      //Check status code
      if(!error)
      {
         //Save elliptic curve parameters
         signature->curve = curve;

         //Copy integer R
         error = ecScalarImport(signature->r, EC_MAX_ORDER_SIZE,
            elsEcdsaArgs.signature, orderLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Copy integer S
            error = ecScalarImport(signature->s, EC_MAX_ORDER_SIZE,
               elsEcdsaArgs.signature + orderLen, orderLen,
               EC_SCALAR_FORMAT_BIG_ENDIAN);
         }
      }

      //Release exclusive access to the ELS module
      osReleaseMutex(&mcxn947CryptoMutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LENGTH;
   }

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
   error_t error;
   size_t modLen;
   size_t orderLen;
   const uint8_t *precG;
   const EcCurve *curve;
   mcuxClEcc_Verify_Param_t verifyParam;

   //Check parameters
   if(publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(publicKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Initialize status code
   error = NO_ERROR;

   //Get elliptic curve parameters
   curve = publicKey->curve;

   //Check elliptic curve parameters
   if(osStrcmp(curve->name, "secp192r1") == 0)
   {
      precG = SECP192R1_PRECG;
   }
   else if(osStrcmp(curve->name, "secp224r1") == 0)
   {
      precG = SECP224R1_PRECG;
   }
   else if(osStrcmp(curve->name, "secp256k1") == 0)
   {
      precG = SECP256K1_PRECG;
   }
   else if(osStrcmp(curve->name, "secp256r1") == 0)
   {
      precG = SECP256R1_PRECG;
   }
   else if(osStrcmp(curve->name, "secp384r1") == 0)
   {
      precG = SECP384R1_PRECG;
   }
   else if(osStrcmp(curve->name, "secp521r1") == 0)
   {
      precG = SECP521R1_PRECG;
   }
   else if(osStrcmp(curve->name, "brainpoolP256r1") == 0)
   {
      precG = BRAINPOOLP256R1_PRECG;
   }
   else if(osStrcmp(curve->name, "brainpoolP384r1") == 0)
   {
      precG = BRAINPOOLP384R1_PRECG;
   }
   else if(osStrcmp(curve->name, "brainpoolP512r1") == 0)
   {
      precG = BRAINPOOLP512R1_PRECG;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Get the length of the modulus, in bytes
   modLen = (curve->fieldSize + 7) / 8;
   //Get the length of the order, in bytes
   orderLen = (curve->orderSize + 7) / 8;

   //Check the length of the operands
   if(modLen <= 66 && orderLen <= 66)
   {
      //Acquire exclusive access to the ELS module
      osAcquireMutex(&mcxn947CryptoMutex);

      //Copy domain parameters
      ecScalarExport(curve->p, (modLen + 3) / 4, elsEcdsaArgs.p, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->a, (modLen + 3) / 4, elsEcdsaArgs.a, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->b, (modLen + 3) / 4, elsEcdsaArgs.b, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->g.x, (modLen + 3) / 4, elsEcdsaArgs.g, modLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->g.y, (modLen + 3) / 4, elsEcdsaArgs.g + modLen,
         modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(curve->q, (modLen + 3) / 4, elsEcdsaArgs.q, orderLen,
         EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Copy public key
      ecScalarExport(publicKey->q.x, (modLen + 3) / 4, elsEcdsaArgs.publicKey,
         modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(publicKey->q.y, (modLen + 3) / 4, elsEcdsaArgs.publicKey +
         modLen, modLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Copy signature
      ecScalarExport(signature->r, (modLen + 3) / 4, elsEcdsaArgs.signature,
         orderLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      ecScalarExport(signature->s, (modLen + 3) / 4, elsEcdsaArgs.signature +
         orderLen, orderLen, EC_SCALAR_FORMAT_BIG_ENDIAN);

      //Set point multiplication parameters
      verifyParam.curveParam.pA = elsEcdsaArgs.a;
      verifyParam.curveParam.pB = elsEcdsaArgs.b;
      verifyParam.curveParam.pP = elsEcdsaArgs.p;
      verifyParam.curveParam.pG = elsEcdsaArgs.g;
      verifyParam.curveParam.pN = elsEcdsaArgs.q;
      verifyParam.curveParam.misc = (orderLen << 8) | modLen;
      verifyParam.pPrecG = precG;
      verifyParam.pHash = digest;
      verifyParam.pSignature = elsEcdsaArgs.signature;
      verifyParam.pPublicKey = elsEcdsaArgs.publicKey;
      verifyParam.pOutputR = elsEcdsaArgs.r;
      verifyParam.optLen = mcuxClEcc_Sign_Param_optLen_Pack(digestLen);

      //Verify ECDSA signature
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEcc_Verify(
         &elsSession, &verifyParam));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Verify))
      {
         error = ERROR_FAILURE;
      }
      else if(status == MCUXCLECC_STATUS_OK)
      {
         error = NO_ERROR;
      }
      else if(status == MCUXCLECC_STATUS_INVALID_SIGNATURE)
      {
         error = ERROR_INVALID_SIGNATURE;
      }
      else
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();

      //Release exclusive access to the ELS module
      osReleaseMutex(&mcxn947CryptoMutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LENGTH;
   }

   //Return status code
   return error;
}

#endif
#if (X25519_SUPPORT == ENABLED)

/**
 * @brief X25519 function (scalar multiplication on Curve25519)
 * @param[out] r Output u-coordinate
 * @param[in] k Input scalar
 * @param[in] u Input u-coordinate
 * @return Error code
 **/

error_t x25519(uint8_t *r, const uint8_t *k, const uint8_t *u)
{
   error_t error;
   uint32_t n;

   //Point to the private and public key descriptors
   mcuxClKey_Handle_t privKeyHandle = (mcuxClKey_Handle_t) elsMontDhArgs.privKeyDesc;
   mcuxClKey_Handle_t pubKeyHandle = (mcuxClKey_Handle_t) elsMontDhArgs.pubKeyDesc;

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn947CryptoMutex);

   //Load input scalar
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClKey_init(&elsSession,
      privKeyHandle, mcuxClKey_Type_Ecc_MontDH_Curve25519_PrivateKey, k,
      MCUXCLECC_MONTDH_CURVE25519_SIZE_PRIVATEKEY));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) ||
      status != MCUXCLKEY_STATUS_OK)
   {
      error = ERROR_FAILURE;
   }

   //End of function call
   MCUX_CSSL_FP_FUNCTION_CALL_END();

   //Check status code
   if(!error)
   {
      //Load input u-coordinate
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClKey_init(&elsSession,
         pubKeyHandle, mcuxClKey_Type_Ecc_MontDH_Curve25519_PublicKey, u,
         MCUXCLECC_MONTDH_CURVE25519_SIZE_PUBLICKEY));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) ||
         status != MCUXCLKEY_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Perform scalar multiplication
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEcc_MontDH_KeyAgreement(
         &elsSession, privKeyHandle, pubKeyHandle, elsMontDhArgs.sharedSecret, &n));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_KeyAgreement) ||
         status != MCUXCLECC_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Copy output u-coordinate
      osMemcpy(r, elsMontDhArgs.sharedSecret, n);
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn947CryptoMutex);

   //Return status code
   return error;
}

#endif
#if (X448_SUPPORT == ENABLED)

/**
 * @brief X448 function (scalar multiplication on Curve448)
 * @param[out] r Output u-coordinate
 * @param[in] k Input scalar
 * @param[in] u Input u-coordinate
 * @return Error code
 **/

error_t x448(uint8_t *r, const uint8_t *k, const uint8_t *u)
{
   error_t error;
   uint32_t n;

   //Point to the private and public key descriptors
   mcuxClKey_Handle_t privKeyHandle = (mcuxClKey_Handle_t) elsMontDhArgs.privKeyDesc;
   mcuxClKey_Handle_t pubKeyHandle = (mcuxClKey_Handle_t) elsMontDhArgs.pubKeyDesc;

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn947CryptoMutex);

   //Load input scalar
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClKey_init(&elsSession,
      privKeyHandle, mcuxClKey_Type_Ecc_MontDH_Curve448_PrivateKey, k,
      MCUXCLECC_MONTDH_CURVE448_SIZE_PRIVATEKEY));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) ||
      status != MCUXCLKEY_STATUS_OK)
   {
      error = ERROR_FAILURE;
   }

   //End of function call
   MCUX_CSSL_FP_FUNCTION_CALL_END();

   //Check status code
   if(!error)
   {
      //Load input u-coordinate
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClKey_init(&elsSession,
         pubKeyHandle, mcuxClKey_Type_Ecc_MontDH_Curve448_PublicKey, u,
         MCUXCLECC_MONTDH_CURVE448_SIZE_PUBLICKEY));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) ||
         status != MCUXCLKEY_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Perform scalar multiplication
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEcc_MontDH_KeyAgreement(
         &elsSession, privKeyHandle, pubKeyHandle, elsMontDhArgs.sharedSecret, &n));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_KeyAgreement) ||
         status != MCUXCLECC_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Copy output u-coordinate
      osMemcpy(r, elsMontDhArgs.sharedSecret, n);
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn947CryptoMutex);

   //Return status code
   return error;
}

#endif
#if (ED25519_SUPPORT == ENABLED)

/**
 * @brief EdDSA signature generation
 * @param[in] privateKey Signer's EdDSA private key (32 bytes)
 * @param[in] publicKey Signer's EdDSA public key (32 bytes)
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed25519ph scheme
 * @param[out] signature EdDSA signature (64 bytes)
 * @return Error code
 **/

error_t ed25519GenerateSignature(const uint8_t *privateKey,
   const uint8_t *publicKey, const void *message, size_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature)
{
   error_t error;
   uint32_t n;
   const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *protocolDesc;

   //Point to the private and public key descriptors
   mcuxClKey_Handle_t privKeyHandle = (mcuxClKey_Handle_t) elsEddsaArgs.privKeyDesc;
   mcuxClKey_Handle_t pubKeyHandle = (mcuxClKey_Handle_t) elsEddsaArgs.pubKeyDesc;

   //Ed25519ph scheme is not supported
   if(flag != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn947CryptoMutex);

   //Initialize private key
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClKey_init(&elsSession,
      privKeyHandle, mcuxClKey_Type_EdDSA_Ed25519_Priv, elsEddsaArgs.privKeyData,
      MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEYDATA));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) ||
      status != MCUXCLKEY_STATUS_OK)
   {
      error = ERROR_FAILURE;
   }

   //End of function call
   MCUX_CSSL_FP_FUNCTION_CALL_END();

   //Check status code
   if(!error)
   {
      //Initialize public key
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClKey_init(&elsSession,
         pubKeyHandle, mcuxClKey_Type_EdDSA_Ed25519_Pub, elsEddsaArgs.pubKeyData,
         MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) ||
         status != MCUXCLKEY_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Load private key
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token,
         mcuxClEcc_EdDSA_InitPrivKeyInputMode(&elsSession,
         (mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *) &elsEddsaArgs.keyPairDesc,
         privateKey));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_InitPrivKeyInputMode) ||
         status != MCUXCLECC_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Derive the public key from the private key
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token,
         mcuxClEcc_EdDSA_GenerateKeyPair(&elsSession,
         (mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *) &elsEddsaArgs.keyPairDesc,
         privKeyHandle, pubKeyHandle));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateKeyPair) ||
         status != MCUXCLECC_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Ed25519ctx scheme?
      if(context != NULL)
      {
         //Point to the protocol descriptor
         protocolDesc = (mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *) elsEddsaArgs.protocolDesc;

         //Generate Ed25519ctx protocol descriptor
         MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token,
            mcuxClEcc_EdDSA_GenerateProtocolDescriptor(&elsSession,
            &mcuxClEcc_EdDSA_DomainParams_Ed25519,
            (mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *) protocolDesc,
            MCUXCLECC_EDDSA_PHFLAG_ZERO, context, contextLen));

         //Check the protection token and the return value
         if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateProtocolDescriptor) ||
            status != MCUXCLECC_STATUS_OK)
         {
            error = ERROR_FAILURE;
         }

         //End of function call
         MCUX_CSSL_FP_FUNCTION_CALL_END();
      }
      else
      {
         //Point to the protocol descriptor
         protocolDesc = &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor;
      }
   }

   //Check status code
   if(!error)
   {
      //Generate Ed25519 signature
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token,
         mcuxClEcc_EdDSA_GenerateSignature(&elsSession, privKeyHandle,
         protocolDesc, message, messageLen, elsEddsaArgs.signature, &n));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateSignature) ||
         status != MCUXCLECC_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Copy signature
      osMemcpy(signature, elsEddsaArgs.signature, n);
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn947CryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief EdDSA signature verification
 * @param[in] publicKey Signer's EdDSA public key (32 bytes)
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed25519ph scheme
 * @param[in] signature EdDSA signature (64 bytes)
 * @return Error code
 **/

error_t ed25519VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen, uint8_t flag,
   const uint8_t *signature)
{
   error_t error;
   const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *protocolDesc;

   //Point to the public key descriptor
   mcuxClKey_Handle_t pubKeyHandle = (mcuxClKey_Handle_t) elsEddsaArgs.pubKeyDesc;

   //Ed25519ph scheme is not supported
   if(flag != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn947CryptoMutex);

   //Load public key
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClKey_init(&elsSession,
      pubKeyHandle, mcuxClKey_Type_EdDSA_Ed25519_Pub, publicKey,
      MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY));

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) ||
      status != MCUXCLKEY_STATUS_OK)
   {
      error = ERROR_FAILURE;
   }

   //End of function call
   MCUX_CSSL_FP_FUNCTION_CALL_END();

   //Check status code
   if(!error)
   {
      //Ed25519ctx scheme?
      if(context != NULL)
      {
         //Point to the protocol descriptor
         protocolDesc = (mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *) elsEddsaArgs.protocolDesc;

         //Generate Ed25519ctx protocol descriptor
         MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token,
            mcuxClEcc_EdDSA_GenerateProtocolDescriptor(&elsSession,
            &mcuxClEcc_EdDSA_DomainParams_Ed25519,
            (mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *) protocolDesc,
            MCUXCLECC_EDDSA_PHFLAG_ZERO, context, contextLen));

         //Check the protection token and the return value
         if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateProtocolDescriptor) ||
            status != MCUXCLECC_STATUS_OK)
         {
            error = ERROR_FAILURE;
         }

         //End of function call
         MCUX_CSSL_FP_FUNCTION_CALL_END();
      }
      else
      {
         //Point to the protocol descriptor
         protocolDesc = &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor;
      }
   }

   //Check status code
   if(!error)
   {
      //Copy signature
      osMemcpy(elsEddsaArgs.signature, signature, ED25519_SIGNATURE_LEN);

      //Verify Ed25519 signature
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token,
         mcuxClEcc_EdDSA_VerifySignature(&elsSession, pubKeyHandle,
         protocolDesc, message, messageLen, elsEddsaArgs.signature,
         ED25519_SIGNATURE_LEN));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature))
      {
         error = ERROR_FAILURE;
      }
      else if(status == MCUXCLECC_STATUS_OK)
      {
         error = NO_ERROR;
      }
      else if(status == MCUXCLECC_STATUS_INVALID_SIGNATURE)
      {
         error = ERROR_INVALID_SIGNATURE;
      }
      else
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn947CryptoMutex);

   //Return status code
   return error;
}

#endif
#endif
