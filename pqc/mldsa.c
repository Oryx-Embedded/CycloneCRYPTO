/**
 * @file mldsa.c
 * @brief ML-DSA (Edwards-Curve Digital Signature Algorithm)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pqc/mldsa.h"
#include "debug.h"

//Check crypto library configuration
#if (MLDSA44_SUPPORT == ENABLED || MLDSA65_SUPPORT == ENABLED || \
   MLDSA87_SUPPORT == ENABLED)

//Dependencies (liboqs)
#include <oqs/oqs.h>

//ML-DSA-44 object identifier (2.16.840.1.101.3.4.3.17)
const uint8_t MLDSA44_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
//ML-DSA-65 object identifier (2.16.840.1.101.3.4.3.18)
const uint8_t MLDSA65_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
//ML-DSA-87 object identifier (2.16.840.1.101.3.4.3.19)
const uint8_t MLDSA87_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};


/**
 * @brief Initialize an ML-DSA public key
 * @param[in] key Pointer to the ML-DSA public key to initialize
 **/

void mldsaInitPublicKey(MldsaPublicKey *key)
{
   //Initialize security level
   key->level = 0;

   //Initialize public key
   key->pk = NULL;
   key->pkLen = 0;
}


/**
 * @brief Release an ML-DSA public key
 * @param[in] key Pointer to the ML-DSA public key to free
 **/

void mldsaFreePublicKey(MldsaPublicKey *key)
{
   //Release public key
   if(key->pk != NULL)
   {
      osMemset(key->pk, 0, key->pkLen);
      cryptoFreeMem(key->pk);
   }

   //Clear public key structure
   osMemset(key, 0, sizeof(MldsaPublicKey));
}


/**
 * @brief Initialize an ML-DSA private key
 * @param[in] key Pointer to the ML-DSA private key to initialize
 **/

void mldsaInitPrivateKey(MldsaPrivateKey *key)
{
   //Initialize security level
   key->level = 0;

   //Initialize seed
   key->seed = NULL;
   key->seedLen = 0;

   //Initialize secret key
   key->sk = NULL;
   key->skLen = 0;
}


/**
 * @brief Release an ML-DSA private key
 * @param[in] key Pointer to the ML-DSA public key to free
 **/

void mldsaFreePrivateKey(MldsaPrivateKey *key)
{
   //Release seed
   if(key->seed != NULL)
   {
      osMemset(key->seed, 0, key->seedLen);
      cryptoFreeMem(key->seed);
   }

   //Release secret key
   if(key->sk != NULL)
   {
      osMemset(key->sk, 0, key->skLen);
      cryptoFreeMem(key->sk);
   }

   //Clear private key structure
   osMemset(key, 0, sizeof(MldsaPrivateKey));
}


/**
 * @brief Import an ML-DSA public key
 * @param[out] key ML-DSA public key
 * @param[in] level Security level
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @return Error code
 **/

error_t mldsaImportPublicKey(MldsaPublicKey *key, uint_t level,
   const uint8_t *input, size_t length)
{
   size_t pkLen;

   //Check parameters
   if(key == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

#if (MLDSA44_SUPPORT == ENABLED)
   //ML-DSA-44 parameter set?
   if(level == MLDSA44_SECURITY_LEVEL)
   {
      //The public key is a 1312-byte octet string
      pkLen = MLDSA44_PUBLIC_KEY_LEN;
   }
   else
#endif
#if (MLDSA65_SUPPORT == ENABLED)
   //ML-DSA-65 parameter set?
   if(level == MLDSA65_SECURITY_LEVEL)
   {
      //The public key is a 1952-byte octet string
      pkLen = MLDSA65_PUBLIC_KEY_LEN;
   }
   else
#endif
#if (MLDSA87_SUPPORT == ENABLED)
   //ML-DSA-87 parameter set?
   if(level == MLDSA87_SECURITY_LEVEL)
   {
      //The public key is a 2592-byte octet string
      pkLen = MLDSA87_PUBLIC_KEY_LEN;
   }
#endif
   //Invalid parameter set?
   else
   {
      //Report an error
      return ERROR_INVALID_PARAMETER;
   }

   //Check the length of the public key
   if(length != pkLen)
      return ERROR_INVALID_LENGTH;

   //Release the public key, if any
   if(key->pk != NULL)
   {
      osMemset(key->pk, 0, key->pkLen);
      cryptoFreeMem(key->pk);
      key->pk = NULL;
      key->pkLen = 0;
   }

   //Allocate a memory block to hold the public key
   key->pk = cryptoAllocMem(pkLen);
   //Failed to allocate memory?
   if(key->pk == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Save security level
   key->level = level;

   //Copy the public key
   osMemcpy(key->pk, input, pkLen);
   key->pkLen = pkLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an ML-DSA public key
 * @param[in] key ML-DSA public key
 * @param[out] output Pointer to the octet string (optional parameter)
 * @param[out] written Length of the resulting octet string, in bytes
 * @return Error code
 **/

error_t mldsaExportPublicKey(const MldsaPublicKey *key, uint8_t *output,
   size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && written != NULL)
   {
      //Valid parameter set?
      if(key->level != 0 && key->pkLen != 0)
      {
         //If the output parameter is NULL, then the function calculates the
         //length of the octet string without copying any data
         if(output != NULL)
         {
            //Copy the private key
            osMemcpy(output, key->pk, key->pkLen);
         }

         //Length of the resulting octet string
         *written = key->pkLen;
      }
      else
      {
         //Invalid parameter set
         error = ERROR_INVALID_KEY;
      }
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
 * @brief Import an ML-DSA private key
 * @param[out] key ML-DSA private key
 * @param[in] level Security level
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @return Error code
 **/

error_t mldsaImportPrivateKey(MldsaPrivateKey *key, uint_t level,
   const uint8_t *input, size_t length)
{
   size_t skLen;

   //Check parameters
   if(key == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

#if (MLDSA44_SUPPORT == ENABLED)
   //ML-DSA-44 parameter set?
   if(level == MLDSA44_SECURITY_LEVEL)
   {
      //The private key is a 2560-byte octet string
      skLen = MLDSA44_PRIVATE_KEY_LEN;
   }
   else
#endif
#if (MLDSA65_SUPPORT == ENABLED)
   //ML-DSA-65 parameter set?
   if(level == MLDSA65_SECURITY_LEVEL)
   {
      //The private key is a 4032-byte octet string
      skLen = MLDSA65_PRIVATE_KEY_LEN;
   }
   else
#endif
#if (MLDSA87_SUPPORT == ENABLED)
   //ML-DSA-87 parameter set?
   if(level == MLDSA87_SECURITY_LEVEL)
   {
      //The private key is a 4896-byte octet string
      skLen = MLDSA87_PRIVATE_KEY_LEN;
   }
#endif
   //Invalid parameter set?
   else
   {
      //Report an error
      return ERROR_INVALID_PARAMETER;
   }

   //Check the length of the private key
   if(length != skLen)
      return ERROR_INVALID_LENGTH;

   //Release the private key, if any
   if(key->sk != NULL)
   {
      osMemset(key->sk, 0, key->skLen);
      cryptoFreeMem(key->sk);
      key->sk = NULL;
      key->skLen = 0;
   }

   //Allocate a memory block to hold the private key
   key->sk = cryptoAllocMem(skLen);
   //Failed to allocate memory?
   if(key->sk == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Save security level
   key->level = level;

   //Copy the private key
   osMemcpy(key->sk, input, skLen);
   key->skLen = skLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an ML-DSA private key
 * @param[in] key ML-DSA private key
 * @param[out] output Pointer to the octet string (optional parameter)
 * @param[out] written Length of the octet string, in bytes
 * @return Error code
 **/

error_t mldsaExportPrivateKey(const MldsaPrivateKey *key, uint8_t *output,
   size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && written != NULL)
   {
      //Valid parameter set?
      if(key->level != 0 && key->skLen != 0)
      {
         //If the output parameter is NULL, then the function calculates the
         //length of the octet string without copying any data
         if(output != NULL)
         {
            //Copy the private key
            osMemcpy(output, key->sk, key->skLen);
         }

         //Length of the resulting octet string
         *written = key->skLen;
      }
      else
      {
         //Invalid parameter set
         error = ERROR_INVALID_KEY;
      }
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
 * @brief Import an ML-DSA seed
 * @param[out] key ML-DSA private key
 * @param[in] level Security level
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @return Error code
 **/

error_t mldsaImportSeed(MldsaPrivateKey *key, uint_t level,
   const uint8_t *input, size_t length)
{
   size_t seedLen;

   //Check parameters
   if(key == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

#if (MLDSA44_SUPPORT == ENABLED)
   //ML-DSA-44 parameter set?
   if(level == MLDSA44_SECURITY_LEVEL)
   {
      //The seed is a fixed 32-byte octet string
      seedLen = MLDSA44_SEED_LEN;
   }
   else
#endif
#if (MLDSA65_SUPPORT == ENABLED)
   //ML-DSA-65 parameter set?
   if(level == MLDSA65_SECURITY_LEVEL)
   {
      //The seed is a fixed 32-byte octet string
      seedLen = MLDSA65_SEED_LEN;
   }
   else
#endif
#if (MLDSA87_SUPPORT == ENABLED)
   //ML-DSA-87 parameter set?
   if(level == MLDSA87_SECURITY_LEVEL)
   {
      //The seed is a fixed 32-byte octet string
      seedLen = MLDSA87_SEED_LEN;
   }
#endif
   //Invalid parameter set?
   else
   {
      //Report an error
      return ERROR_INVALID_PARAMETER;
   }

   //Check the length of the seed
   if(length != seedLen)
      return ERROR_INVALID_LENGTH;

   //Release the seed, if any
   if(key->seed != NULL)
   {
      osMemset(key->seed, 0, key->seedLen);
      cryptoFreeMem(key->seed);
      key->seed = NULL;
      key->seedLen = 0;
   }

   //Allocate a memory block to hold the seed
   key->seed = cryptoAllocMem(seedLen);
   //Failed to allocate memory?
   if(key->seed == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Save security level
   key->level = level;

   //Copy the seed
   osMemcpy(key->seed, input, seedLen);
   key->seedLen = seedLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an ML-DSA seed
 * @param[in] key ML-DSA private key
 * @param[out] output Pointer to the octet string (optional parameter)
 * @param[out] written Length of the octet string, in bytes
 * @return Error code
 **/

error_t mldsaExportSeed(const MldsaPrivateKey *key, uint8_t *output,
   size_t *written)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && written != NULL)
   {
      //Valid parameter set?
      if(key->level != 0 && key->seedLen != 0)
      {
         //If the output parameter is NULL, then the function calculates the
         //length of the octet string without copying any data
         if(output != NULL)
         {
            //Copy the seed
            osMemcpy(output, key->seed, key->seedLen);
         }

         //Length of the resulting octet string
         *written = key->seedLen;
      }
      else
      {
         //Invalid parameter set
         error = ERROR_INVALID_KEY;
      }
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
 * @brief ML-DSA-44 signature generation
 * @param[in] secretKey Pointer to the secret key (2560 bytes)
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Context string (a byte string of 255 or fewer bytes)
 * @param[in] contextLen Length of the context, in bytes
 * @param[out] signature ML-DSA-44 signature (2420 bytes)
 * @return Error code
 **/

error_t mldsa44GenerateSignature(const uint8_t *secretKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   uint8_t *signature)
{
#if (MLDSA44_SUPPORT == ENABLED)
   OQS_STATUS status;
   size_t signatureLen;

   //Generate ML-DSA-44 signature
   status = OQS_SIG_ml_dsa_44_sign_with_ctx_str(signature, &signatureLen, message,
      messageLen, context, contextLen, secretKey);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ML-DSA-65 signature generation
 * @param[in] secretKey Pointer to the secret key (4032 bytes)
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Context string (a byte string of 255 or fewer bytes)
 * @param[in] contextLen Length of the context, in bytes
 * @param[out] signature ML-DSA-65 signature (3309 bytes)
 * @return Error code
 **/

error_t mldsa65GenerateSignature(const uint8_t *secretKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   uint8_t *signature)
{
#if (MLDSA65_SUPPORT == ENABLED)
   OQS_STATUS status;
   size_t signatureLen;

   //Generate ML-DSA-65 signature
   status = OQS_SIG_ml_dsa_65_sign_with_ctx_str(signature, &signatureLen, message,
      messageLen, context, contextLen, secretKey);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ML-DSA-87 signature generation
 * @param[in] secretKey Pointer to the secret key (4896 bytes)
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] signature ML-DSA-87 signature (4627 bytes)
 * @return Error code
 **/

error_t mldsa87GenerateSignature(const uint8_t *secretKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   uint8_t *signature)
{
#if (MLDSA87_SUPPORT == ENABLED)
   OQS_STATUS status;
   size_t signatureLen;

   //Generate ML-DSA-87 signature
   status = OQS_SIG_ml_dsa_87_sign_with_ctx_str(signature, &signatureLen, message,
      messageLen, context, contextLen, secretKey);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ML-DSA-44 signature verification
 * @param[in] publicKey Pointer to the public key (1312 bytes)
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Context string (a byte string of 255 or fewer bytes)
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] signature ML-DSA-44 signature (2420 bytes)
 * @return Error code
 **/

error_t mldsa44VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   const uint8_t *signature)
{
#if (MLDSA44_SUPPORT == ENABLED)
   OQS_STATUS status;

   //Verify ML-DSA-44 signature
   status = OQS_SIG_ml_dsa_44_verify_with_ctx_str(message, messageLen, signature,
      MLDSA44_SIGNATURE_LEN, context, contextLen, publicKey);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ML-DSA-65 signature verification
 * @param[in] publicKey Pointer to the public key (1952 bytes)
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Context string (a byte string of 255 or fewer bytes)
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] signature ML-DSA-65 signature (3309 bytes)
 * @return Error code
 **/

error_t mldsa65VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   const uint8_t *signature)
{
#if (MLDSA65_SUPPORT == ENABLED)
   OQS_STATUS status;

   //Verify ML-DSA-65 signature
   status = OQS_SIG_ml_dsa_65_verify_with_ctx_str(message, messageLen, signature,
      MLDSA65_SIGNATURE_LEN, context, contextLen, publicKey);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ML-DSA-87 signature verification
 * @param[in] publicKey Pointer to the public key (2592 bytes)
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Context string (a byte string of 255 or fewer bytes)
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] signature ML-DSA-87 signature (4627 bytes)
 * @return Error code
 **/

error_t mldsa87VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen,
   const uint8_t *signature)
{
#if (MLDSA87_SUPPORT == ENABLED)
   OQS_STATUS status;

   //Verify ML-DSA-87 signature
   status = OQS_SIG_ml_dsa_87_verify_with_ctx_str(message, messageLen, signature,
      MLDSA87_SIGNATURE_LEN, context, contextLen, publicKey);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
