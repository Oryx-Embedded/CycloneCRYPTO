/**
 * @file gd32w5xx_crypto_pkc.c
 * @brief GD32W5 public-key hardware accelerator (PKCAU)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.3.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "gd32w51x.h"
#include "core/crypto.h"
#include "hardware/gd32w5xx/gd32w5xx_crypto.h"
#include "hardware/gd32w5xx/gd32w5xx_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ecdsa.h"
#include "ecc/curve25519.h"
#include "ecc/curve448.h"
#include "debug.h"

//Check crypto library configuration
#if (GD32W5XX_CRYPTO_PKC_SUPPORT == ENABLED)


/**
 * @brief PKCAU module initialization
 * @return Error code
 **/

error_t pkcauInit(void)
{
   //Enable PKCAU peripheral clock
   rcu_periph_clock_enable(RCU_PKCAU);

   //Reset the PKCAU peripheral
   PKCAU_CTL = 0;

   //Enable the PKCAU peripheral
   while((PKCAU_CTL & PKCAU_CTL_PKCAUEN) == 0)
   {
      PKCAU_CTL = PKCAU_CTL_PKCAUEN;
   }

   //Clear flags
   PKCAU_STATC = PKCAU_STATC_ADDRERRC | PKCAU_STATC_RAMERRC | PKCAU_STATC_ENDC;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import byte array
 * @param[in] src Pointer to the byte array
 * @param[in] srcLen Length of the array to be copied, in bytes
 * @param[in] destLen Length of the operand, in bits
 * @param[in] offset PKCAU ram offset
 **/

void pkcauImportArray(const uint8_t *src, size_t srcLen, uint_t destLen,
   uint_t offset)
{
   uint_t i;
   uint_t j;
   uint32_t temp;

   //Retrieve the length of the operand, in words
   destLen = (destLen + 31) / 32;

   //Copy the array to the PKCAU RAM
   for(i = 0, j = 0; i < srcLen; i++)
   {
      switch(i % 4)
      {
      case 0:
         temp = src[srcLen - i - 1];
         break;
      case 1:
         temp |= src[srcLen - i - 1] << 8;
         break;
      case 2:
         temp |= src[srcLen - i - 1] << 16;
         break;
      default:
         temp |= src[srcLen - i - 1] << 24;
         PKCAU_RAM[offset + j] = temp;
         j++;
         break;
      }
   }

   //Pad the operand with zeroes
   for(; i < (destLen * 4); i++)
   {
      switch(i % 4)
      {
      case 0:
         temp = 0;
         break;
      case 3:
         PKCAU_RAM[offset + j] = temp;
         j++;
         break;
      default:
         break;
      }
   }

   //An additional word with all bits equal to zero must be added
   PKCAU_RAM[offset + j] = 0;
}


/**
 * @brief Import multiple-precision integer
 * @param[in] a Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKCAU ram offset
 **/

void pkcauImportMpi(const Mpi *a, uint_t length, uint_t offset)
{
   uint_t i;
   uint_t n;

   //Retrieve the length of the operand, in words
   length = (length + 31) / 32;

   //Get the actual length of the multiple-precision integer, in words
   n = mpiGetLength(a);

   //Copy the multiple-precision integer to the PKCAU RAM
   for(i = 0; i < n && i < length; i++)
   {
      PKCAU_RAM[offset + i] = a->data[i];
   }

   //Pad the operand with zeroes
   for(; i < length; i++)
   {
      PKCAU_RAM[offset + i] = 0;
   }

   //An additional word with all bits equal to zero must be added
   PKCAU_RAM[offset + i] = 0;
}


/**
 * @brief Export multiple-precision integer
 * @param[out] r Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKCAU ram offset
 * @return Error code
 **/

error_t pkcauExportMpi(Mpi *r, uint_t length, uint_t offset)
{
   error_t error;
   uint_t i;

   //Retrieve the length of the operand, in words
   length = (length + 31) / 32;

   //Skip trailing zeroes
   while(length > 0 && PKCAU_RAM[offset + length - 1] == 0)
   {
      length--;
   }

   //Ajust the size of the multiple precision integer
   error = mpiGrow(r, length);

   //Check status code
   if(!error)
   {
      //Copy the multiple-precision integer from the PKCAU RAM
      for(i = 0; i < length; i++)
      {
         r->data[i] = PKCAU_RAM[offset + i];
      }

      //Pad the resulting value with zeroes
      for(; i < r->size; i++)
      {
         r->data[i] = 0;
      }

      //Set the sign
      r->sign = 1;
   }

   //Return status code
   return error;
}


/**
 * @brief Modular exponentiation
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t pkcauModExp(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   uint_t modLen;
   uint_t expLen;
   uint32_t temp;

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(p);
   //Retrieve the length of the exponent, in bits
   expLen = mpiGetBitLength(e);

   //Check the length of the operands
   if(modLen <= PKCAU_MAX_ROS && expLen <= PKCAU_MAX_ROS)
   {
      //Reduce the operand first
      error = mpiMod(r, a, p);

      //Check status code
      if(!error)
      {
         //Acquire exclusive access to the PKCAU module
         osAcquireMutex(&gd32w5xxCryptoMutex);

         //Specify the length of the operand, in bits
         PKCAU_RAM[PKCAU_MOD_EXP_IN_OP_LEN] = modLen;
         //Specify the length of the exponent, in bits
         PKCAU_RAM[PKCAU_MOD_EXP_IN_EXP_LEN] = expLen;

         //Load input arguments into the PKCAU internal RAM
         pkcauImportMpi(r, modLen, PKCAU_MOD_EXP_IN_A);
         pkcauImportMpi(e, expLen, PKCAU_MOD_EXP_IN_E);
         pkcauImportMpi(p, modLen, PKCAU_MOD_EXP_IN_N);

         //Disable interrupts
         PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

         //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
         //which is to be executed
         temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
         PKCAU_CTL = temp | PKCAU_MODE_MOD_EXP;

         //Then assert the START bit in PKCAU_CTL register
         PKCAU_CTL |= PKCAU_CTL_START;

         //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
         //indicating that the computation is complete
         while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
         {
         }

         //Read the result data from the PKCAU internal RAM
         error = pkcauExportMpi(r, modLen, PKCAU_MOD_EXP_OUT_R);

         //Then clear ENDC bit by setting ENDC bit in PKCAU_STATC
         PKCAU_STATC = PKCAU_STATC_ENDC;

         //Release exclusive access to the PKCAU module
         osReleaseMutex(&gd32w5xxCryptoMutex);
      }
   }
   else
   {
      //Perform modular exponentiation
      error = mpiExpMod(r, a, e, p);
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

error_t pkcauRsaCrtExp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;
   uint_t nLen;
   uint_t pLen;
   uint_t qLen;
   uint_t dpLen;
   uint_t dqLen;
   uint_t qinvLen;
   uint32_t temp;

   //Retrieve the length of the private key
   nLen = mpiGetBitLength(&key->n);
   pLen = mpiGetBitLength(&key->p);
   qLen = mpiGetBitLength(&key->q);
   dpLen = mpiGetBitLength(&key->dp);
   dqLen = mpiGetBitLength(&key->dq);
   qinvLen = mpiGetBitLength(&key->qinv);

   //Check the length of the operands
   if(nLen <= PKCAU_MAX_ROS && pLen <= (nLen / 2) && qLen <= (nLen / 2) &&
      dpLen <= (nLen / 2) && dqLen <= (nLen / 2) && qinvLen <= (nLen / 2))
   {
      //Acquire exclusive access to the PKCAU module
      osAcquireMutex(&gd32w5xxCryptoMutex);

      //Specify the length of the operand, in bits
      PKCAU_RAM[PKCAU_RSA_CRT_EXP_IN_MOD_LEN] = nLen;

      //Load input arguments into the PKCAU internal RAM
      pkcauImportMpi(&key->p, nLen / 2, PKCAU_RSA_CRT_EXP_IN_P);
      pkcauImportMpi(&key->q, nLen / 2, PKCAU_RSA_CRT_EXP_IN_Q);
      pkcauImportMpi(&key->dp, nLen / 2, PKCAU_RSA_CRT_EXP_IN_DP);
      pkcauImportMpi(&key->dq, nLen / 2, PKCAU_RSA_CRT_EXP_IN_DQ);
      pkcauImportMpi(&key->qinv, nLen / 2, PKCAU_RSA_CRT_EXP_IN_QINV);
      pkcauImportMpi(c, nLen, PKCAU_RSA_CRT_EXP_IN_A);

      //Disable interrupts
      PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

      //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
      //which is to be executed
      temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
      PKCAU_CTL = temp | PKCAU_MODE_CRT_EXP;

      //Then assert the START bit in PKCAU_CTL register
      PKCAU_CTL |= PKCAU_CTL_START;

      //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
      //indicating that the computation is complete
      while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
      {
      }

      //Read the result data from the PKCAU internal RAM
      error = pkcauExportMpi(m, nLen, PKCAU_RSA_CRT_EXP_OUT_R);

      //Then clear ENDC bit by setting ENDC bit in PKCAU_STATC
      PKCAU_STATC = PKCAU_STATC_ENDC;

      //Release exclusive access to the PKCAU module
      osReleaseMutex(&gd32w5xxCryptoMutex);
   }
   else
   {
      Mpi m1;
      Mpi m2;
      Mpi h;

      //Initialize multiple-precision integers
      mpiInit(&m1);
      mpiInit(&m2);
      mpiInit(&h);

      //Compute m1 = c ^ dP mod p
      error = pkcauModExp(&m1, c, &key->dp, &key->p);

      //Check status code
      if(!error)
      {
         //Compute m2 = c ^ dQ mod q
         error = pkcauModExp(&m2, c, &key->dq, &key->q);
      }

      //Check status code
      if(!error)
      {
         //Let h = (m1 - m2) * qInv mod p
         error = mpiSub(&h, &m1, &m2);
      }

      //Check status code
      if(!error)
      {
         error = mpiMulMod(&h, &h, &key->qinv, &key->p);
      }

      //Check status code
      if(!error)
      {
         //Let m = m2 + q * h
         error = mpiMul(m, &key->q, &h);
      }

      //Check status code
      if(!error)
      {
         error = mpiAdd(m, m, &m2);
      }

      //Free previously allocated memory
      mpiFree(&m1);
      mpiFree(&m2);
      mpiFree(&h);
   }

   //Return status code
   return error;
}


/**
 * @brief RSA encryption primitive
 * @param[in] key RSA public key
 * @param[in] m Message representative
 * @param[out] c Ciphertext representative
 * @return Error code
 **/

error_t rsaep(const RsaPublicKey *key, const Mpi *m, Mpi *c)
{
   size_t nLen;
   size_t eLen;

   //Retrieve the length of the public key
   nLen = mpiGetLength(&key->n);
   eLen = mpiGetLength(&key->e);

   //Sanity check
   if(nLen == 0 || eLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The message representative m shall be between 0 and n - 1
   if(mpiCompInt(m, 0) < 0 || mpiComp(m, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Perform modular exponentiation (c = m ^ e mod n)
   return pkcauModExp(c, m, &key->e, &key->n);
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
      error = pkcauRsaCrtExp(key, c, m);
   }
   else if(mpiGetLength(&key->n) > 0 && mpiGetLength(&key->d) > 0)
   {
      //Perform modular exponentiation (without CRT)
      error = pkcauModExp(m, c, &key->d, &key->n);
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
   uint_t modLen;
   uint_t scalarLen;
   uint32_t temp;

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(&params->p);
   //Retrieve the length of the scalar, in bits
   scalarLen = mpiGetBitLength(d);

   //Check the length of the operands
   if(modLen <= PKCAU_MAX_EOS && scalarLen <= PKCAU_MAX_EOS)
   {
      //Acquire exclusive access to the PKCAU module
      osAcquireMutex(&gd32w5xxCryptoMutex);

      //Specify the length of the modulus, in bits
      PKCAU_RAM[PKCAU_ECC_MUL_IN_MOD_LEN] = modLen;
      //Specify the length of the scalar, in bits
      PKCAU_RAM[PKCAU_ECC_MUL_IN_SCALAR_LEN] = scalarLen;
      //Set the sign of the coefficient A
      PKCAU_RAM[PKCAU_ECC_MUL_IN_A_SIGN] = 0;

      //Load input arguments into the PKCAU internal RAM
      pkcauImportMpi(&params->p, modLen, PKCAU_ECC_MUL_IN_P);
      pkcauImportMpi(&params->a, modLen, PKCAU_ECC_MUL_IN_A);
      pkcauImportMpi(d, scalarLen, PKCAU_ECC_MUL_IN_K);
      pkcauImportMpi(&s->x, modLen, PKCAU_ECC_MUL_IN_X);
      pkcauImportMpi(&s->y, modLen, PKCAU_ECC_MUL_IN_Y);

      //Disable interrupts
      PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

      //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
      //which is to be executed
      temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
      PKCAU_CTL = temp | PKCAU_MODE_ECC_MUL;

      //Then assert the START bit in PKCAU_CTL register
      PKCAU_CTL |= PKCAU_CTL_START;

      //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
      //indicating that the computation is complete
      while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
      {
      }

      //Copy the x-coordinate of the result
      error = pkcauExportMpi(&r->x, modLen, PKCAU_ECC_MUL_OUT_X);

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = pkcauExportMpi(&r->y, modLen, PKCAU_ECC_MUL_OUT_Y);
      }

      //Check status code
      if(!error)
      {
         //Set the z-coordinate of the result
         error = mpiSetValue(&r->z, 1);
      }

      //Then clear ENDC bit by setting ENDC bit in PKCAU_STATC
      PKCAU_STATC = PKCAU_STATC_ENDC;

      //Release exclusive access to the PKCAU module
      osReleaseMutex(&gd32w5xxCryptoMutex);
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
   uint32_t temp;
   Mpi k;

   //Check parameters
   if(params == NULL || privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(&params->p);
   //Retrieve the length of the base point order, in bits
   orderLen = mpiGetBitLength(&params->q);

   //Check the length of the operands
   if(modLen > PKCAU_MAX_EOS || orderLen > PKCAU_MAX_EOS)
      return ERROR_FAILURE;

   //Initialize multiple precision integers
   mpiInit(&k);

   //Generate a random number k such as 0 < k < q - 1
   error = mpiRandRange(&k, &params->q, prngAlgo, prngContext);

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the PKCAU module
      osAcquireMutex(&gd32w5xxCryptoMutex);

      //Specify the length of the modulus, in bits
      PKCAU_RAM[PKCAU_ECDSA_SIGN_IN_MOD_LEN] = modLen;
      //Specify the length of the base point order, in bits
      PKCAU_RAM[PKCAU_ECDSA_SIGN_IN_ORDER_LEN] = orderLen;
      //Set the sign of the coefficient A
      PKCAU_RAM[PKCAU_ECDSA_SIGN_IN_A_SIGN] = 0;

      //Load input arguments into the PKCAU internal RAM
      pkcauImportMpi(&params->p, modLen, PKCAU_ECDSA_SIGN_IN_P);
      pkcauImportMpi(&params->a, modLen, PKCAU_ECDSA_SIGN_IN_A);
      pkcauImportMpi(&params->g.x, modLen, PKCAU_ECDSA_SIGN_IN_GX);
      pkcauImportMpi(&params->g.y, modLen, PKCAU_ECDSA_SIGN_IN_GY);
      pkcauImportMpi(&params->q, orderLen, PKCAU_ECDSA_SIGN_IN_N);
      pkcauImportMpi(&privateKey->d, orderLen, PKCAU_ECDSA_SIGN_IN_D);
      pkcauImportMpi(&k, orderLen, PKCAU_ECDSA_SIGN_IN_K);

      //Keep the leftmost bits of the hash value
      digestLen = MIN(digestLen, (orderLen + 7) / 8);
      //Load the hash value into the PKCAU internal RAM
      pkcauImportArray(digest, digestLen, orderLen, PKCAU_ECDSA_SIGN_IN_Z);

      //Clear error code
      PKCAU_RAM[PKCAU_ECDSA_SIGN_OUT_ERROR] = PKCAU_STATUS_INVALID;

      //Disable interrupts
      PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

      //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
      //which is to be executed
      temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
      PKCAU_CTL = temp | PKCAU_MODE_ECDSA_SIGN;

      //Then assert the START bit in PKCAU_CTL register
      PKCAU_CTL |= PKCAU_CTL_START;

      //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
      //indicating that the computation is complete
      while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
      {
      }

      //Successful computation?
      if(PKCAU_RAM[PKCAU_ECDSA_SIGN_OUT_ERROR] == PKCAU_STATUS_SUCCESS)
      {
         error = NO_ERROR;
      }
      else
      {
         error = ERROR_FAILURE;
      }

      //Check status code
      if(!error)
      {
         //Copy integer R
         error = pkcauExportMpi(&signature->r, orderLen, PKCAU_ECDSA_SIGN_OUT_R);
      }

      //Check status code
      if(!error)
      {
         //Copy integer S
         error = pkcauExportMpi(&signature->s, orderLen, PKCAU_ECDSA_SIGN_OUT_S);
      }

      //Then clear ENDC bit by setting ENDC bit in PKCAU_STATC
      PKCAU_STATC = PKCAU_STATC_ENDC;

      //Release exclusive access to the PKCAU module
      osReleaseMutex(&gd32w5xxCryptoMutex);
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
   uint32_t temp;

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

   //Retrieve the length of the modulus, in bits
   modLen = mpiGetBitLength(&params->p);
   //Retrieve the length of the base point order, in bits
   orderLen = mpiGetBitLength(&params->q);

   //Check the length of the operands
   if(modLen > PKCAU_MAX_EOS || orderLen > PKCAU_MAX_EOS)
      return ERROR_FAILURE;

   //Acquire exclusive access to the PKCAU module
   osAcquireMutex(&gd32w5xxCryptoMutex);

   //Specify the length of the modulus, in bits
   PKCAU_RAM[PKCAU_ECDSA_VERIF_IN_MOD_LEN] = modLen;
   //Specify the length of the base point order, in bits
   PKCAU_RAM[PKCAU_ECDSA_VERIF_IN_ORDER_LEN] = orderLen;
   //Set the sign of the coefficient A
   PKCAU_RAM[PKCAU_ECDSA_VERIF_IN_A_SIGN] = 0;

   //Load input arguments into the PKCAU internal RAM
   pkcauImportMpi(&params->p, modLen, PKCAU_ECDSA_VERIF_IN_P);
   pkcauImportMpi(&params->a, modLen, PKCAU_ECDSA_VERIF_IN_A);
   pkcauImportMpi(&params->g.x, modLen, PKCAU_ECDSA_VERIF_IN_GX);
   pkcauImportMpi(&params->g.y, modLen, PKCAU_ECDSA_VERIF_IN_GY);
   pkcauImportMpi(&params->q, orderLen, PKCAU_ECDSA_VERIF_IN_N);
   pkcauImportMpi(&publicKey->q.x, modLen, PKCAU_ECDSA_VERIF_IN_QX);
   pkcauImportMpi(&publicKey->q.y, modLen, PKCAU_ECDSA_VERIF_IN_QY);
   pkcauImportMpi(&signature->r, orderLen, PKCAU_ECDSA_VERIF_IN_R);
   pkcauImportMpi(&signature->s, orderLen, PKCAU_ECDSA_VERIF_IN_S);

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, (orderLen + 7) / 8);
   //Load the hash value into the PKCAU internal RAM
   pkcauImportArray(digest, digestLen, orderLen, PKCAU_ECDSA_VERIF_IN_Z);

   //Clear result
   PKCAU_RAM[PKCAU_ECDSA_VERIF_OUT_RES] = PKCAU_STATUS_INVALID;

   //Disable interrupts
   PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

   //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
   //which is to be executed
   temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
   PKCAU_CTL = temp | PKCAU_MODE_ECDSA_VERIFICATION;

   //Then assert the START bit in PKCAU_CTL register
   PKCAU_CTL |= PKCAU_CTL_START;

   //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
   //indicating that the computation is complete
   while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
   {
   }

   //Test if the ECDSA signature is valid
   if(PKCAU_RAM[PKCAU_ECDSA_VERIF_OUT_RES] == PKCAU_STATUS_SUCCESS)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_INVALID_SIGNATURE;
   }

   //Then clear ENDC bit by setting ENDC bit in PKCAU_STATC
   PKCAU_STATC = PKCAU_STATC_ENDC;

   //Release exclusive access to the PKCAU module
   osReleaseMutex(&gd32w5xxCryptoMutex);

   //Return status code
   return error;
}


#if (X25519_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve25519Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint64_t temp;
   uint32_t u[16];

   //Acquire exclusive access to the PKCAU module
   osAcquireMutex(&gd32w5xxCryptoMutex);

   //Specify the length of the operands, in bits
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_OP_LEN] = 255;

   //Load the first operand into the PKCAU internal RAM
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A] = a[0];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 1] = a[1];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 2] = a[2];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 3] = a[3];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 4] = a[4];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 5] = a[5];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 6] = a[6];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 7] = a[7];

   //An additional word with all bits equal to zero must be added
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 8] = 0;

   //Load the second operand into the PKCAU internal RAM
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B] = b[0];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 1] = b[1];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 2] = b[2];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 3] = b[3];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 4] = b[4];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 5] = b[5];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 6] = b[6];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 7] = b[7];

   //An additional word with all bits equal to zero must be added
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 8] = 0;

   //Disable interrupts
   PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

   //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
   //which is to be executed
   temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
   PKCAU_CTL = temp | PKCAU_MODE_ARITHMETIC_MUL;

   //Then assert the START bit in PKCAU_CTL register
   PKCAU_CTL |= PKCAU_CTL_START;

   //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
   //indicating that the computation is complete
   while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
   {
   }

   //Read the result data from the PKCAU internal RAM
   u[0] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R];
   u[1] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 1];
   u[2] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 2];
   u[3] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 3];
   u[4] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 4];
   u[5] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 5];
   u[6] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 6];
   u[7] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 7];
   u[8] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 8];
   u[9] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 9];
   u[10] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 10];
   u[11] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 11];
   u[12] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 12];
   u[13] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 13];
   u[14] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 14];
   u[15] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 15];

   //Then clear ENDC bit by setting ENDC bit in PKCAU_STATC
   PKCAU_STATC = PKCAU_STATC_ENDC;

   //Release exclusive access to the PKCAU module
   osReleaseMutex(&gd32w5xxCryptoMutex);

   //Reduce bit 255 (2^255 = 19 mod p)
   temp = (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (first pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      temp += (uint64_t) u[i + 8] * 38;
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce bit 256 (2^256 = 38 mod p)
   temp *= 38;
   //Reduce bit 255 (2^255 = 19 mod p)
   temp += (u[7] >> 31) * 19;
   //Mask the most significant bit
   u[7] &= 0x7FFFFFFF;

   //Perform fast modular reduction (second pass)
   for(i = 0; i < 8; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve25519Red(r, u);
}

#endif
#if (X448_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)

/**
 * @brief Modular multiplication
 * @param[out] r Resulting integer R = (A * B) mod p
 * @param[in] a An integer such as 0 <= A < p
 * @param[in] b An integer such as 0 <= B < p
 **/

void curve448Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint_t i;
   uint64_t c;
   uint64_t temp;
   uint32_t u[28];

   //Acquire exclusive access to the PKCAU module
   osAcquireMutex(&gd32w5xxCryptoMutex);

   //Specify the length of the operands, in bits
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_OP_LEN] = 448;

   //Load the first operand into the PKCAU internal RAM
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A] = a[0];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 1] = a[1];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 2] = a[2];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 3] = a[3];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 4] = a[4];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 5] = a[5];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 6] = a[6];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 7] = a[7];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 8] = a[8];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 9] = a[9];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 10] = a[10];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 11] = a[11];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 12] = a[12];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 13] = a[13];

   //An additional word with all bits equal to zero must be added
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_A + 14] = 0;

   //Load the second operand into the PKCAU internal RAM
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B] = b[0];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 1] = b[1];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 2] = b[2];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 3] = b[3];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 4] = b[4];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 5] = b[5];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 6] = b[6];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 7] = b[7];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 8] = b[8];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 9] = b[9];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 10] = b[10];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 11] = b[11];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 12] = b[12];
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 13] = b[13];

   //An additional word with all bits equal to zero must be added
   PKCAU_RAM[PKCAU_ARITH_MUL_IN_B + 14] = 0;

   //Disable interrupts
   PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

   //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
   //which is to be executed
   temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
   PKCAU_CTL = temp | PKCAU_MODE_ARITHMETIC_MUL;

   //Then assert the START bit in PKCAU_CTL register
   PKCAU_CTL |= PKCAU_CTL_START;

   //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
   //indicating that the computation is complete
   while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
   {
   }

   //Read the result data from the PKCAU internal RAM
   u[0] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R];
   u[1] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 1];
   u[2] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 2];
   u[3] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 3];
   u[4] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 4];
   u[5] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 5];
   u[6] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 6];
   u[7] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 7];
   u[8] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 8];
   u[9] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 9];
   u[10] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 10];
   u[11] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 11];
   u[12] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 12];
   u[13] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 13];
   u[14] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 14];
   u[15] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 15];
   u[16] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 16];
   u[17] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 17];
   u[18] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 18];
   u[19] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 19];
   u[20] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 20];
   u[21] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 21];
   u[22] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 22];
   u[23] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 23];
   u[24] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 24];
   u[25] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 25];
   u[26] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 26];
   u[27] = PKCAU_RAM[PKCAU_ARITH_MUL_OUT_R + 27];

   //Then clear ENDC bit by setting ENDC bit in PKCAU_STATC
   PKCAU_STATC = PKCAU_STATC_ENDC;

   //Release exclusive access to the PKCAU module
   osReleaseMutex(&gd32w5xxCryptoMutex);

   //Perform fast modular reduction (first pass)
   for(temp = 0, i = 0; i < 7; i++)
   {
      temp += u[i];
      temp += u[i + 14];
      temp += u[i + 21];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(i = 7; i < 14; i++)
   {
      temp += u[i];
      temp += u[i + 7];
      temp += u[i + 14];
      temp += u[i + 14];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Perform fast modular reduction (second pass)
   for(c = temp, i = 0; i < 7; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(temp += c, i = 7; i < 14; i++)
   {
      temp += u[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //Reduce non-canonical values
   curve448Red(r, u, (uint32_t) temp);
}

#endif
#endif
