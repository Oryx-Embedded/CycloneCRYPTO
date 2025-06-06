/**
 * @file stm32n6xx_crypto_pkc.c
 * @brief STM32N6 public-key hardware accelerator (PKA)
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
#include "stm32n6xx.h"
#include "stm32n6xx_hal.h"
#include "core/crypto.h"
#include "hardware/stm32n6xx/stm32n6xx_crypto.h"
#include "hardware/stm32n6xx/stm32n6xx_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/ecdsa.h"
#include "debug.h"

//Check crypto library configuration
#if (STM32N6XX_CRYPTO_PKC_SUPPORT == ENABLED)


/**
 * @brief PKA module initialization
 * @return Error code
 **/

error_t pkaInit(void)
{
   //Enable PKA peripheral clock
   __HAL_RCC_PKA_CLK_ENABLE();

   //Reset the PKA peripheral
   PKA->CR = 0;

   //Enable the PKA peripheral
   while((PKA->CR & PKA_CR_EN) == 0)
   {
      PKA->CR = PKA_CR_EN;
   }

   //Clear flags
   PKA->CLRFR = PKA_CLRFR_ADDRERRFC | PKA_CLRFR_RAMERRFC | PKA_CLRFR_PROCENDFC;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import byte array
 * @param[in] src Pointer to the byte array
 * @param[in] srcLen Length of the array to be copied, in bytes
 * @param[in] destLen Length of the operand, in bits
 * @param[in] offset PKA ram offset
 **/

void pkaImportArray(const uint8_t *src, size_t srcLen, uint_t destLen,
   uint_t offset)
{
   uint_t i;
   uint_t j;
   uint32_t temp;

   //Get the length of the operand, in 64-bit words
   destLen = (destLen + 63) / 64;

   //Copy the array to the PKA RAM
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
         PKA->RAM[offset + j] = temp;
         j++;
         break;
      }
   }

   //Pad the operand with zeroes
   for(; i < (destLen * 8); i++)
   {
      switch(i % 4)
      {
      case 0:
         temp = 0;
         break;
      case 3:
         PKA->RAM[offset + j] = temp;
         j++;
         break;
      default:
         break;
      }
   }

   //An additional 64-bit word with all bits equal to zero must be added
   PKA->RAM[offset + j] = 0;
   PKA->RAM[offset + j + 1] = 0;
}


/**
 * @brief Import scalar
 * @param[in] src Pointer to the scalar
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKA ram offset
 **/

void pkaImportScalar(const uint32_t *src, uint_t length, uint_t offset)
{
   uint_t i;

   //Get the length of the operand, in 32-bit words
   length = (length + 31) / 32;

   //Copy the scalar to the PKA RAM
   for(i = 0; i < length; i++)
   {
      PKA->RAM[offset + i] = src[i];
   }

   //Pad the operand with zeroes
   if((i % 2) != 0)
   {
      PKA->RAM[offset + i] = 0;
      i++;
   }

   //An additional 64-bit word with all bits equal to zero must be added
   PKA->RAM[offset + i] = 0;
   PKA->RAM[offset + i + 1] = 0;
}


/**
 * @brief Import multiple-precision integer
 * @param[in] src Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKA ram offset
 **/

void pkaImportMpi(const Mpi *src, uint_t length, uint_t offset)
{
   uint_t i;
   uint_t n;

   //Get the length of the operand, in 64-bit words
   length = (length + 63) / 64;

   //Get the actual length of the multiple-precision integer, in words
   n = mpiGetLength(src);

   //Copy the multiple-precision integer to the PKA RAM
   for(i = 0; i < n && i < (length * 2); i++)
   {
      PKA->RAM[offset + i] = src->data[i];
   }

   //Pad the operand with zeroes
   for(; i < (length * 2); i++)
   {
      PKA->RAM[offset + i] = 0;
   }

   //An additional 64-bit word with all bits equal to zero must be added
   PKA->RAM[offset + i] = 0;
   PKA->RAM[offset + i + 1] = 0;
}


/**
 * @brief Export scalar
 * @param[out] dest Pointer to the scalar
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKA ram offset
 **/

void pkaExportScalar(uint32_t *dest, uint_t length, uint_t offset)
{
   uint_t i;

   //Get the length of the operand, in 32-bit words
   length = (length + 31) / 32;

   //Copy the scalar from the PKA RAM
   for(i = 0; i < length; i++)
   {
      dest[i] = PKA->RAM[offset + i];
   }
}


/**
 * @brief Export multiple-precision integer
 * @param[out] dest Pointer to the multiple-precision integer
 * @param[in] length Length of the operand, in bits
 * @param[in] offset PKA ram offset
 * @return Error code
 **/

error_t pkaExportMpi(Mpi *dest, uint_t length, uint_t offset)
{
   error_t error;
   uint_t i;

   //Get the length of the operand, in 32-bit words
   length = (length + 31) / 32;

   //Skip trailing zeroes
   while(length > 0 && PKA->RAM[offset + length - 1] == 0)
   {
      length--;
   }

   //Ajust the size of the multiple precision integer
   error = mpiGrow(dest, length);

   //Check status code
   if(!error)
   {
      //Copy the multiple-precision integer from the PKA RAM
      for(i = 0; i < length; i++)
      {
         dest->data[i] = PKA->RAM[offset + i];
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

error_t mpiExpMod(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
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
   if(modLen <= PKA_MAX_ROS && expLen <= PKA_MAX_ROS)
   {
      //Reduce the operand first
      error = mpiMod(r, a, p);

      //Check status code
      if(!error)
      {
         //Acquire exclusive access to the PKA module
         osAcquireMutex(&stm32n6xxCryptoMutex);

         //Specify the length of the operand, in bits
         PKA->RAM[PKA_MODULAR_EXP_IN_OP_NB_BITS] = modLen;
         PKA->RAM[PKA_MODULAR_EXP_IN_OP_NB_BITS + 1] = 0;

         //Specify the length of the exponent, in bits
         PKA->RAM[PKA_MODULAR_EXP_IN_EXP_NB_BITS] = expLen;
         PKA->RAM[PKA_MODULAR_EXP_IN_EXP_NB_BITS + 1] = 0;

         //Load input arguments into the PKA internal RAM
         pkaImportMpi(r, modLen, PKA_MODULAR_EXP_IN_EXPONENT_BASE);
         pkaImportMpi(e, expLen, PKA_MODULAR_EXP_IN_EXPONENT);
         pkaImportMpi(p, modLen, PKA_MODULAR_EXP_IN_MODULUS);

         //Disable interrupts
         PKA->CR &= ~(PKA_CR_ADDRERRIE | PKA_CR_RAMERRIE | PKA_CR_PROCENDIE);

         //Write in the MODE field of PKA_CR register, specifying the operation
         //which is to be executed
         temp = PKA->CR & ~PKA_CR_MODE;
         PKA->CR = temp | (PKA_CR_MODE_MODULAR_EXP << PKA_CR_MODE_Pos);

         //Then assert the START bit in PKA_CR register
         PKA->CR |= PKA_CR_START;

         //Wait until the PROCENDF bit in the PKA_SR register is set to 1,
         //indicating that the computation is complete
         while((PKA->SR & PKA_SR_PROCENDF) == 0)
         {
         }

         //Read the result data from the PKA internal RAM
         error = pkaExportMpi(r, modLen, PKA_MODULAR_EXP_OUT_RESULT);

         //Then clear PROCENDF bit by setting PROCENDFC bit in PKA_CLRFR
         PKA->CLRFR = PKA_CLRFR_PROCENDFC;

         //Release exclusive access to the PKA module
         osReleaseMutex(&stm32n6xxCryptoMutex);
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

#endif
#if (RSA_SUPPORT == ENABLED)

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
   if(nLen <= PKA_MAX_ROS && pLen <= (nLen / 2) && qLen <= (nLen / 2) &&
      dpLen <= (nLen / 2) && dqLen <= (nLen / 2) && qinvLen <= (nLen / 2))
   {
      //Acquire exclusive access to the PKA module
      osAcquireMutex(&stm32n6xxCryptoMutex);

      //Specify the length of the operand, in bits
      PKA->RAM[PKA_RSA_CRT_EXP_IN_MOD_NB_BITS] = nLen;
      PKA->RAM[PKA_RSA_CRT_EXP_IN_MOD_NB_BITS + 1] = 0;

      //Load input arguments into the PKA internal RAM
      pkaImportMpi(&key->p, nLen / 2, PKA_RSA_CRT_EXP_IN_PRIME_P);
      pkaImportMpi(&key->q, nLen / 2, PKA_RSA_CRT_EXP_IN_PRIME_Q);
      pkaImportMpi(&key->dp, nLen / 2, PKA_RSA_CRT_EXP_IN_DP_CRT);
      pkaImportMpi(&key->dq, nLen / 2, PKA_RSA_CRT_EXP_IN_DQ_CRT);
      pkaImportMpi(&key->qinv, nLen / 2, PKA_RSA_CRT_EXP_IN_QINV_CRT);
      pkaImportMpi(c, nLen, PKA_RSA_CRT_EXP_IN_EXPONENT_BASE);

      //Disable interrupts
      PKA->CR &= ~(PKA_CR_ADDRERRIE | PKA_CR_RAMERRIE | PKA_CR_PROCENDIE);

      //Write in the MODE field of PKA_CR register, specifying the operation
      //which is to be executed
      temp = PKA->CR & ~PKA_CR_MODE;
      PKA->CR = temp | (PKA_CR_MODE_RSA_CRT_EXP << PKA_CR_MODE_Pos);

      //Then assert the START bit in PKA_CR register
      PKA->CR |= PKA_CR_START;

      //Wait until the PROCENDF bit in the PKA_SR register is set to 1,
      //indicating that the computation is complete
      while((PKA->SR & PKA_SR_PROCENDF) == 0)
      {
      }

      //Read the result data from the PKA internal RAM
      error = pkaExportMpi(m, nLen, PKA_RSA_CRT_EXP_OUT_RESULT);

      //Then clear PROCENDF bit by setting PROCENDFC bit in PKA_CLRFR
      PKA->CLRFR = PKA_CLRFR_PROCENDFC;

      //Release exclusive access to the PKA module
      osReleaseMutex(&stm32n6xxCryptoMutex);
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
   if(modLen <= PKA_MAX_EOS && orderLen <= PKA_MAX_EOS)
   {
      //Acquire exclusive access to the PKA module
      osAcquireMutex(&stm32n6xxCryptoMutex);

      //Specify the length of the modulus, in bits
      PKA->RAM[PKA_ECC_SCALAR_MUL_IN_OP_NB_BITS] = modLen;
      PKA->RAM[PKA_ECC_SCALAR_MUL_IN_OP_NB_BITS + 1] = 0;

      //Specify the length of the scalar, in bits
      PKA->RAM[PKA_ECC_SCALAR_MUL_IN_EXP_NB_BITS] = orderLen;
      PKA->RAM[PKA_ECC_SCALAR_MUL_IN_EXP_NB_BITS + 1] = 0;

      //Set the sign of the coefficient A
      PKA->RAM[PKA_ECC_SCALAR_MUL_IN_A_COEFF_SIGN] = 0;
      PKA->RAM[PKA_ECC_SCALAR_MUL_IN_A_COEFF_SIGN + 1] = 0;

      //Load input arguments into the PKA internal RAM
      pkaImportScalar(curve->p, modLen, PKA_ECC_SCALAR_MUL_IN_MOD_GF);
      pkaImportScalar(curve->a, modLen, PKA_ECC_SCALAR_MUL_IN_A_COEFF);
      pkaImportScalar(curve->b, modLen, PKA_ECC_SCALAR_MUL_IN_B_COEFF);
      pkaImportScalar(curve->q, orderLen, PKA_ECC_SCALAR_MUL_IN_N_PRIME_ORDER);
      pkaImportScalar(d, orderLen, PKA_ECC_SCALAR_MUL_IN_K);
      pkaImportScalar(s->x, modLen, PKA_ECC_SCALAR_MUL_IN_INITIAL_POINT_X);
      pkaImportScalar(s->y, modLen, PKA_ECC_SCALAR_MUL_IN_INITIAL_POINT_Y);

      //Clear error code
      PKA->RAM[PKA_ECC_SCALAR_MUL_OUT_ERROR] = PKA_STATUS_INVALID;

      //Disable interrupts
      PKA->CR &= ~(PKA_CR_ADDRERRIE | PKA_CR_RAMERRIE | PKA_CR_PROCENDIE);

      //Write in the MODE field of PKA_CR register, specifying the operation
      //which is to be executed
      temp = PKA->CR & ~PKA_CR_MODE;
      PKA->CR = temp | (PKA_CR_MODE_ECC_MUL << PKA_CR_MODE_Pos);

      //Then assert the START bit in PKA_CR register
      PKA->CR |= PKA_CR_START;

      //Wait until the PROCENDF bit in the PKA_SR register is set to 1,
      //indicating that the computation is complete
      while((PKA->SR & PKA_SR_PROCENDF) == 0)
      {
      }

      //Successful computation?
      if(PKA->RAM[PKA_ECC_SCALAR_MUL_OUT_ERROR] == PKA_STATUS_SUCCESS)
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
         //Copy the x-coordinate of the result
         ecScalarSetInt(r->x, 0, EC_MAX_MODULUS_SIZE);
         pkaExportScalar(r->x, modLen, PKA_ECC_SCALAR_MUL_OUT_RESULT_X);

         //Copy the y-coordinate of the result
         ecScalarSetInt(r->y, 0, EC_MAX_MODULUS_SIZE);
         pkaExportScalar(r->y, modLen, PKA_ECC_SCALAR_MUL_OUT_RESULT_Y);

         //Set the z-coordinate of the result
         ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);
      }

      //Then clear PROCENDF bit by setting PROCENDFC bit in PKA_CLRFR
      PKA->CLRFR = PKA_CLRFR_PROCENDFC;

      //Release exclusive access to the PKA module
      osReleaseMutex(&stm32n6xxCryptoMutex);
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
   if(modLen > PKA_MAX_EOS || orderLen > PKA_MAX_EOS)
      return ERROR_FAILURE;

   //Generate a random number k such as 0 < k < q - 1
   error = ecScalarRand(curve, k, prngAlgo, prngContext);

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the PKA module
      osAcquireMutex(&stm32n6xxCryptoMutex);

      //Specify the length of the modulus, in bits
      PKA->RAM[PKA_ECDSA_SIGN_IN_MOD_NB_BITS] = modLen;
      PKA->RAM[PKA_ECDSA_SIGN_IN_MOD_NB_BITS + 1] = 0;

      //Specify the length of the base point order, in bits
      PKA->RAM[PKA_ECDSA_SIGN_IN_ORDER_NB_BITS] = orderLen;
      PKA->RAM[PKA_ECDSA_SIGN_IN_ORDER_NB_BITS + 1] = 0;

      //Set the sign of the coefficient A
      PKA->RAM[PKA_ECDSA_SIGN_IN_A_COEFF_SIGN] = 0;
      PKA->RAM[PKA_ECDSA_SIGN_IN_A_COEFF_SIGN + 1] = 0;

      //Load input arguments into the PKA internal RAM
      pkaImportScalar(curve->p, modLen, PKA_ECDSA_SIGN_IN_MOD_GF);
      pkaImportScalar(curve->a, modLen, PKA_ECDSA_SIGN_IN_A_COEFF);
      pkaImportScalar(curve->b, modLen, PKA_ECDSA_SIGN_IN_B_COEFF);
      pkaImportScalar(curve->g.x, modLen, PKA_ECDSA_SIGN_IN_INITIAL_POINT_X);
      pkaImportScalar(curve->g.y, modLen, PKA_ECDSA_SIGN_IN_INITIAL_POINT_Y);
      pkaImportScalar(curve->q, orderLen, PKA_ECDSA_SIGN_IN_ORDER_N);
      pkaImportScalar(privateKey->d, orderLen, PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D);
      pkaImportScalar(k, orderLen, PKA_ECDSA_SIGN_IN_K);

      //Keep the leftmost bits of the hash value
      digestLen = MIN(digestLen, (orderLen + 7) / 8);
      //Load the hash value into the PKA internal RAM
      pkaImportArray(digest, digestLen, orderLen, PKA_ECDSA_SIGN_IN_HASH_E);

      //Clear error code
      PKA->RAM[PKA_ECDSA_SIGN_OUT_ERROR] = PKA_STATUS_INVALID;

      //Disable interrupts
      PKA->CR &= ~(PKA_CR_ADDRERRIE | PKA_CR_RAMERRIE | PKA_CR_PROCENDIE);

      //Write in the MODE field of PKA_CR register, specifying the operation
      //which is to be executed
      temp = PKA->CR & ~PKA_CR_MODE;
      PKA->CR = temp | (PKA_CR_MODE_ECDSA_SIGN << PKA_CR_MODE_Pos);

      //Then assert the START bit in PKA_CR register
      PKA->CR |= PKA_CR_START;

      //Wait until the PROCENDF bit in the PKA_SR register is set to 1,
      //indicating that the computation is complete
      while((PKA->SR & PKA_SR_PROCENDF) == 0)
      {
      }

      //Successful computation?
      if(PKA->RAM[PKA_ECDSA_SIGN_OUT_ERROR] == PKA_STATUS_SUCCESS)
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
         pkaExportScalar(signature->r, orderLen, PKA_ECDSA_SIGN_OUT_SIGNATURE_R);

         //Copy integer S
         ecScalarSetInt(signature->s, 0, EC_MAX_ORDER_SIZE);
         pkaExportScalar(signature->s, orderLen, PKA_ECDSA_SIGN_OUT_SIGNATURE_S);
      }

      //Then clear PROCENDF bit by setting PROCENDFC bit in PKA_CLRFR
      PKA->CLRFR = PKA_CLRFR_PROCENDFC;

      //Release exclusive access to the PKA module
      osReleaseMutex(&stm32n6xxCryptoMutex);
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
   if(modLen > PKA_MAX_EOS || orderLen > PKA_MAX_EOS)
      return ERROR_FAILURE;

   //Acquire exclusive access to the PKA module
   osAcquireMutex(&stm32n6xxCryptoMutex);

   //Specify the length of the modulus, in bits
   PKA->RAM[PKA_ECDSA_VERIF_IN_MOD_NB_BITS] = modLen;
   PKA->RAM[PKA_ECDSA_VERIF_IN_MOD_NB_BITS + 1] = 0;

   //Specify the length of the base point order, in bits
   PKA->RAM[PKA_ECDSA_VERIF_IN_ORDER_NB_BITS] = orderLen;
   PKA->RAM[PKA_ECDSA_VERIF_IN_ORDER_NB_BITS + 1] = 0;

   //Set the sign of the coefficient A
   PKA->RAM[PKA_ECDSA_VERIF_IN_A_COEFF_SIGN] = 0;
   PKA->RAM[PKA_ECDSA_VERIF_IN_A_COEFF_SIGN + 1] = 0;

   //Load input arguments into the PKA internal RAM
   pkaImportScalar(curve->p, modLen, PKA_ECDSA_VERIF_IN_MOD_GF);
   pkaImportScalar(curve->a, modLen, PKA_ECDSA_VERIF_IN_A_COEFF);
   pkaImportScalar(curve->g.x, modLen, PKA_ECDSA_VERIF_IN_INITIAL_POINT_X);
   pkaImportScalar(curve->g.y, modLen, PKA_ECDSA_VERIF_IN_INITIAL_POINT_Y);
   pkaImportScalar(curve->q, orderLen, PKA_ECDSA_VERIF_IN_ORDER_N);
   pkaImportScalar(publicKey->q.x, modLen, PKA_ECDSA_VERIF_IN_PUBLIC_KEY_POINT_X);
   pkaImportScalar(publicKey->q.y, modLen, PKA_ECDSA_VERIF_IN_PUBLIC_KEY_POINT_Y);
   pkaImportScalar(signature->r, orderLen, PKA_ECDSA_VERIF_IN_SIGNATURE_R);
   pkaImportScalar(signature->s, orderLen, PKA_ECDSA_VERIF_IN_SIGNATURE_S);

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, (orderLen + 7) / 8);
   //Load the hash value into the PKA internal RAM
   pkaImportArray(digest, digestLen, orderLen, PKA_ECDSA_VERIF_IN_HASH_E);

   //Clear result
   PKA->RAM[PKA_ECDSA_VERIF_OUT_RESULT] = PKA_STATUS_INVALID;

   //Disable interrupts
   PKA->CR &= ~(PKA_CR_ADDRERRIE | PKA_CR_RAMERRIE | PKA_CR_PROCENDIE);

   //Write in the MODE field of PKA_CR register, specifying the operation
   //which is to be executed
   temp = PKA->CR & ~PKA_CR_MODE;
   PKA->CR = temp | (PKA_CR_MODE_ECDSA_VERIFY << PKA_CR_MODE_Pos);

   //Then assert the START bit in PKA_CR register
   PKA->CR |= PKA_CR_START;

   //Wait until the PROCENDF bit in the PKA_SR register is set to 1,
   //indicating that the computation is complete
   while((PKA->SR & PKA_SR_PROCENDF) == 0)
   {
   }

   //Test if the ECDSA signature is valid
   if(PKA->RAM[PKA_ECDSA_VERIF_OUT_RESULT] == PKA_STATUS_SUCCESS)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_INVALID_SIGNATURE;
   }

   //Then clear PROCENDF bit by setting PROCENDFC bit in PKA_CLRFR
   PKA->CLRFR = PKA_CLRFR_PROCENDFC;

   //Release exclusive access to the PKA module
   osReleaseMutex(&stm32n6xxCryptoMutex);

   //Return status code
   return error;
}

#endif
#endif
