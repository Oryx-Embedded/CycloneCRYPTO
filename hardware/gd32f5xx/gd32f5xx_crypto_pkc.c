/**
 * @file gd32f5xx_crypto_pkc.c
 * @brief GD32F5 public-key hardware accelerator (PKCAU)
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
#include "gd32f5xx.h"
#include "core/crypto.h"
#include "hardware/gd32f5xx/gd32f5xx_crypto.h"
#include "hardware/gd32f5xx/gd32f5xx_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/ecdsa.h"
#include "debug.h"

//Check crypto library configuration
#if (GD32F5XX_CRYPTO_PKC_SUPPORT == ENABLED)


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
   PKCAU_STATC = PKCAU_STATC_ADDRERRC | PKCAU_STATC_RAMERRC | PKCAU_STATC_ENDFC;

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

   //Get the length of the operand, in words
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
 * @brief Import scalar
 * @param[in] src Pointer to the scalar
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKCAU ram offset
 **/

void pkcauImportScalar(const uint32_t *src, uint_t length, uint_t offset)
{
   uint_t i;

   //Get the length of the operand, in words
   length = (length + 31) / 32;

   //Copy the scalar to the PKCAU RAM
   for(i = 0; i < length; i++)
   {
      PKCAU_RAM[offset + i] = src[i];
   }

   //An additional word with all bits equal to zero must be added
   PKCAU_RAM[offset + i] = 0;
}


/**
 * @brief Import multiple-precision integer
 * @param[in] src Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKCAU ram offset
 **/

void pkcauImportMpi(const Mpi *src, uint_t length, uint_t offset)
{
   uint_t i;
   uint_t n;

   //Get the length of the operand, in words
   length = (length + 31) / 32;

   //Get the actual length of the multiple-precision integer, in words
   n = mpiGetLength(src);

   //Copy the multiple-precision integer to the PKCAU RAM
   for(i = 0; i < n && i < length; i++)
   {
      PKCAU_RAM[offset + i] = src->data[i];
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
 * @brief Export scalar
 * @param[out] dest Pointer to the scalar
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKCAU ram offset
 **/

void pkcauExportScalar(uint32_t *dest, uint_t length, uint_t offset)
{
   uint_t i;

   //Get the length of the operand, in words
   length = (length + 31) / 32;

   //Copy the scalar from the PKCAU RAM
   for(i = 0; i < length; i++)
   {
      dest[i] = PKCAU_RAM[offset + i];
   }
}


/**
 * @brief Export multiple-precision integer
 * @param[out] dest Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKCAU ram offset
 * @return Error code
 **/

error_t pkcauExportMpi(Mpi *dest, uint_t length, uint_t offset)
{
   error_t error;
   uint_t i;

   //Get the length of the operand, in words
   length = (length + 31) / 32;

   //Skip trailing zeroes
   while(length > 0 && PKCAU_RAM[offset + length - 1] == 0)
   {
      length--;
   }

   //Ajust the size of the multiple precision integer
   error = mpiGrow(dest, length);

   //Check status code
   if(!error)
   {
      //Copy the multiple-precision integer from the PKCAU RAM
      for(i = 0; i < length; i++)
      {
         dest->data[i] = PKCAU_RAM[offset + i];
      }

      //Pad the resulting value with zeroes
      for(; i < dest->size; i++)
      {
         dest->data[i] = 0;
      }

      //Set the sign
      dest->sign = 1;
   }

   //Return status code
   return error;
}


#if (MPI_SUPPORT == ENABLED)

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

   //Get the length of the modulus, in bits
   modLen = mpiGetBitLength(p);
   //Get the length of the exponent, in bits
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
         osAcquireMutex(&gd32f5xxCryptoMutex);

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

         //Data synchronization barrier
         __DSB();

         //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
         //indicating that the computation is complete
         while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
         {
         }

         //Read the result data from the PKCAU internal RAM
         error = pkcauExportMpi(r, modLen, PKCAU_MOD_EXP_OUT_R);

         //Then clear ENDFC bit by setting ENDFC bit in PKCAU_STATC
         PKCAU_STATC = PKCAU_STATC_ENDFC;

         //Release exclusive access to the PKCAU module
         osReleaseMutex(&gd32f5xxCryptoMutex);
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

#endif
#if (RSA_SUPPORT == ENABLED)

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

   //Get the length of the private key
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
      osAcquireMutex(&gd32f5xxCryptoMutex);

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

      //Data synchronization barrier
      __DSB();

      //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
      //indicating that the computation is complete
      while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
      {
      }

      //Read the result data from the PKCAU internal RAM
      error = pkcauExportMpi(m, nLen, PKCAU_RSA_CRT_EXP_OUT_R);

      //Then clear ENDFC bit by setting ENDFC bit in PKCAU_STATC
      PKCAU_STATC = PKCAU_STATC_ENDFC;

      //Release exclusive access to the PKCAU module
      osReleaseMutex(&gd32f5xxCryptoMutex);
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

   //Get the length of the public key
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
   uint_t modLen;
   uint_t orderLen;
   uint32_t temp;

   //Get the length of the modulus, in bits
   modLen = curve->fieldSize;
   //Get the length of the order, in bits
   orderLen = curve->orderSize;

   //Check the length of the operands
   if(modLen <= PKCAU_MAX_EOS && orderLen <= PKCAU_MAX_EOS)
   {
      //Acquire exclusive access to the PKCAU module
      osAcquireMutex(&gd32f5xxCryptoMutex);

      //Specify the length of the modulus, in bits
      PKCAU_RAM[PKCAU_ECC_MUL_IN_MOD_LEN] = modLen;
      //Specify the length of the scalar, in bits
      PKCAU_RAM[PKCAU_ECC_MUL_IN_SCALAR_LEN] = orderLen;
      //Set the sign of the coefficient A
      PKCAU_RAM[PKCAU_ECC_MUL_IN_A_SIGN] = 0;

      //Load input arguments into the PKCAU internal RAM
      pkcauImportScalar(curve->p, modLen, PKCAU_ECC_MUL_IN_P);
      pkcauImportScalar(curve->a, modLen, PKCAU_ECC_MUL_IN_A);
      pkcauImportScalar(d, orderLen, PKCAU_ECC_MUL_IN_K);
      pkcauImportScalar(s->x, modLen, PKCAU_ECC_MUL_IN_X);
      pkcauImportScalar(s->y, modLen, PKCAU_ECC_MUL_IN_Y);

      //Disable interrupts
      PKCAU_CTL &= ~(PKCAU_CTL_ADDRERRIE | PKCAU_CTL_RAMERRIE | PKCAU_CTL_ENDIE);

      //Write in the MODESEL field of PKCAU_CTL register, specifying the operation
      //which is to be executed
      temp = PKCAU_CTL & ~PKCAU_CTL_MODESEL;
      PKCAU_CTL = temp | PKCAU_MODE_ECC_SCALAR_MUL;

      //Then assert the START bit in PKCAU_CTL register
      PKCAU_CTL |= PKCAU_CTL_START;

      //Data synchronization barrier
      __DSB();

      //Wait until the ENDF bit in the PKCAU_STAT register is set to 1,
      //indicating that the computation is complete
      while((PKCAU_STAT & PKCAU_STAT_ENDF) == 0)
      {
      }

      //Copy the x-coordinate of the result
      ecScalarSetInt(r->x, 0, EC_MAX_MODULUS_SIZE);
      pkcauExportScalar(r->x, modLen, PKCAU_ECC_MUL_OUT_X);

      //Copy the y-coordinate of the result
      ecScalarSetInt(r->y, 0, EC_MAX_MODULUS_SIZE);
      pkcauExportScalar(r->y, modLen, PKCAU_ECC_MUL_OUT_Y);

      //Set the z-coordinate of the result
      ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);

      //Then clear ENDFC bit by setting ENDFC bit in PKCAU_STATC
      PKCAU_STATC = PKCAU_STATC_ENDFC;

      //Release exclusive access to the PKCAU module
      osReleaseMutex(&gd32f5xxCryptoMutex);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
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
   uint_t modLen;
   uint_t orderLen;
   uint32_t temp;
   uint32_t k[EC_MAX_ORDER_SIZE];
   const EcCurve *curve;

   //Check parameters
   if(privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get elliptic curve parameters
   curve = privateKey->curve;

   //Get the length of the modulus, in bits
   modLen = curve->fieldSize;
   //Get the length of the order, in bits
   orderLen = curve->orderSize;

   //Check the length of the operands
   if(modLen > PKCAU_MAX_EOS || orderLen > PKCAU_MAX_EOS)
      return ERROR_FAILURE;

   //Generate a random number k such as 0 < k < q - 1
   error = ecScalarRand(curve, k, prngAlgo, prngContext);

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the PKCAU module
      osAcquireMutex(&gd32f5xxCryptoMutex);

      //Specify the length of the modulus, in bits
      PKCAU_RAM[PKCAU_ECDSA_SIGN_IN_MOD_LEN] = modLen;
      //Specify the length of the base point order, in bits
      PKCAU_RAM[PKCAU_ECDSA_SIGN_IN_ORDER_LEN] = orderLen;
      //Set the sign of the coefficient A
      PKCAU_RAM[PKCAU_ECDSA_SIGN_IN_A_SIGN] = 0;

      //Load input arguments into the PKCAU internal RAM
      pkcauImportScalar(curve->p, modLen, PKCAU_ECDSA_SIGN_IN_P);
      pkcauImportScalar(curve->a, modLen, PKCAU_ECDSA_SIGN_IN_A);
      pkcauImportScalar(curve->g.x, modLen, PKCAU_ECDSA_SIGN_IN_GX);
      pkcauImportScalar(curve->g.y, modLen, PKCAU_ECDSA_SIGN_IN_GY);
      pkcauImportScalar(curve->q, orderLen, PKCAU_ECDSA_SIGN_IN_N);
      pkcauImportScalar(privateKey->d, orderLen, PKCAU_ECDSA_SIGN_IN_D);
      pkcauImportScalar(k, orderLen, PKCAU_ECDSA_SIGN_IN_K);

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

      //Data synchronization barrier
      __DSB();

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
         //Save elliptic curve parameters
         signature->curve = curve;

         //Copy integer R
         ecScalarSetInt(signature->r, 0, EC_MAX_ORDER_SIZE);
         pkcauExportScalar(signature->r, orderLen, PKCAU_ECDSA_SIGN_OUT_R);

         //Copy integer S
         ecScalarSetInt(signature->s, 0, EC_MAX_ORDER_SIZE);
         pkcauExportScalar(signature->s, orderLen, PKCAU_ECDSA_SIGN_OUT_S);
      }

      //Then clear ENDFC bit by setting ENDFC bit in PKCAU_STATC
      PKCAU_STATC = PKCAU_STATC_ENDFC;

      //Release exclusive access to the PKCAU module
      osReleaseMutex(&gd32f5xxCryptoMutex);
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
   uint_t modLen;
   uint_t orderLen;
   uint32_t temp;
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

   //Get the length of the modulus, in bits
   modLen = curve->fieldSize;
   //Get the length of the order, in bits
   orderLen = curve->orderSize;

   //Check the length of the operands
   if(modLen > PKCAU_MAX_EOS || orderLen > PKCAU_MAX_EOS)
      return ERROR_FAILURE;

   //Acquire exclusive access to the PKCAU module
   osAcquireMutex(&gd32f5xxCryptoMutex);

   //Specify the length of the modulus, in bits
   PKCAU_RAM[PKCAU_ECDSA_VERIF_IN_MOD_LEN] = modLen;
   //Specify the length of the base point order, in bits
   PKCAU_RAM[PKCAU_ECDSA_VERIF_IN_ORDER_LEN] = orderLen;
   //Set the sign of the coefficient A
   PKCAU_RAM[PKCAU_ECDSA_VERIF_IN_A_SIGN] = 0;

   //Load input arguments into the PKCAU internal RAM
   pkcauImportScalar(curve->p, modLen, PKCAU_ECDSA_VERIF_IN_P);
   pkcauImportScalar(curve->a, modLen, PKCAU_ECDSA_VERIF_IN_A);
   pkcauImportScalar(curve->g.x, modLen, PKCAU_ECDSA_VERIF_IN_GX);
   pkcauImportScalar(curve->g.y, modLen, PKCAU_ECDSA_VERIF_IN_GY);
   pkcauImportScalar(curve->q, orderLen, PKCAU_ECDSA_VERIF_IN_N);
   pkcauImportScalar(publicKey->q.x, modLen, PKCAU_ECDSA_VERIF_IN_QX);
   pkcauImportScalar(publicKey->q.y, modLen, PKCAU_ECDSA_VERIF_IN_QY);
   pkcauImportScalar(signature->r, orderLen, PKCAU_ECDSA_VERIF_IN_R);
   pkcauImportScalar(signature->s, orderLen, PKCAU_ECDSA_VERIF_IN_S);

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

   //Data synchronization barrier
   __DSB();

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

   //Then clear ENDFC bit by setting ENDFC bit in PKCAU_STATC
   PKCAU_STATC = PKCAU_STATC_ENDFC;

   //Release exclusive access to the PKCAU module
   osReleaseMutex(&gd32f5xxCryptoMutex);

   //Return status code
   return error;
}

#endif
#endif
