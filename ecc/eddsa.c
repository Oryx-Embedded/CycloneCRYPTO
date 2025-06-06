/**
 * @file eddsa.c
 * @brief EdDSA (Edwards-Curve Digital Signature Algorithm)
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
#include "ecc/eddsa.h"
#include "debug.h"

//Check crypto library configuration
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)


/**
 * @brief Initialize an EdDSA public key
 * @param[in] key Pointer to the EdDSA public key to initialize
 **/

void eddsaInitPublicKey(EddsaPublicKey *key)
{
   //Initialize elliptic curve parameters
   key->curve = NULL;

   //Initialize public key
   osMemset(key->q, 0, EDDSA_MAX_PUBLIC_KEY_LEN);
}


/**
 * @brief Release an EdDSA public key
 * @param[in] key Pointer to the EdDSA public key to free
 **/

void eddsaFreePublicKey(EddsaPublicKey *key)
{
   //Clear public key
   osMemset(key, 0, sizeof(EddsaPublicKey));
}


/**
 * @brief Initialize an EdDSA private key
 * @param[in] key Pointer to the EdDSA private key to initialize
 **/

void eddsaInitPrivateKey(EddsaPrivateKey *key)
{
   //Initialize elliptic curve parameters
   key->curve = NULL;

   //Initialize private key
   osMemset(key->d, 0, EDDSA_MAX_PRIVATE_KEY_LEN);
   //Initialize private key slot
   key->slot = -1;

   //Initialize public key
   eddsaInitPublicKey(&key->q);
}


/**
 * @brief Release an EdDSA private key
 * @param[in] key Pointer to the EdDSA public key to free
 **/

void eddsaFreePrivateKey(EddsaPrivateKey *key)
{
   //Clear public key
   osMemset(key, 0, sizeof(EddsaPrivateKey));
}


/**
 * @brief EdDSA key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] curve Elliptic curve parameters
 * @param[out] privateKey EdDSA private key
 * @param[out] publicKey EdDSA public key (optional parameter)
 * @return Error code
 **/

error_t eddsaGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EddsaPrivateKey *privateKey,
   EddsaPublicKey *publicKey)
{
   error_t error;

   //Generate a private key
   error = eddsaGeneratePrivateKey(prngAlgo, prngContext, curve,
      privateKey);

   //Check status code
   if(!error)
   {
      //Derive the public key from the private key
      error = eddsaGeneratePublicKey(privateKey, &privateKey->q);
   }

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
 * @brief EdDSA private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] curve Elliptic curve parameters
 * @param[out] privateKey EdDSA private key
 * @return Error code
 **/

error_t eddsaGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EddsaPrivateKey *privateKey)
{
   error_t error;

   //Check parameters
   if(curve != NULL && privateKey != NULL)
   {
      //Initialize private key
      osMemset(privateKey->d, 0, EDDSA_MAX_PRIVATE_KEY_LEN);
      //Initialize public key
      eddsaInitPublicKey(&privateKey->q);

#if (ED25519_SUPPORT == ENABLED)
      //Ed25519 elliptic curve?
      if(curve == ED25519_CURVE)
      {
         //Save elliptic curve parameters
         privateKey->curve = ED25519_CURVE;

         //Generate an Ed25519 private key
         error = ed25519GeneratePrivateKey(prngAlgo, prngContext,
            privateKey->d);
      }
      else
#endif
#if (ED448_SUPPORT == ENABLED)
      //Ed448 elliptic curve?
      if(curve == ED448_CURVE)
      {
         //Save elliptic curve parameters
         privateKey->curve = ED448_CURVE;

         //Generate an Ed448 private key
         error = ed448GeneratePrivateKey(prngAlgo, prngContext,
            privateKey->d);
      }
      else
#endif
      //Unknown algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
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
 * @brief Derive the public key from an EdDSA private key
 * @param[in] privateKey EdDSA private key
 * @param[out] publicKey EdDSA public key
 * @return Error code
 **/

error_t eddsaGeneratePublicKey(const EddsaPrivateKey *privateKey,
   EddsaPublicKey *publicKey)
{
   error_t error;

   //Check parameters
   if(privateKey != NULL && publicKey != NULL)
   {
#if (ED25519_SUPPORT == ENABLED)
      //Ed25519 elliptic curve?
      if(privateKey->curve == ED25519_CURVE)
      {
         //Save elliptic curve parameters
         publicKey->curve = ED25519_CURVE;

         //Derive the public key from the private key
         error = ed25519GeneratePublicKey(privateKey->d, publicKey->q);
      }
      else
#endif
#if (ED448_SUPPORT == ENABLED)
      //Ed448 elliptic curve?
      if(privateKey->curve == ED448_CURVE)
      {
         //Save elliptic curve parameters
         publicKey->curve = ED448_CURVE;

         //Derive the public key from the private key
         error = ed448GeneratePublicKey(privateKey->d, publicKey->q);
      }
      else
#endif
      //Unknown algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
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
 * @brief Import an EdDSA public key
 * @param[out] key EdDSA public key
 * @param[in] curve Elliptic curve parameters
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @return Error code
 **/

error_t eddsaImportPublicKey(EddsaPublicKey *key, const EcCurve *curve,
   const uint8_t *input, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && curve != NULL && input != NULL)
   {
      //Edwards elliptic curve?
      if(curve->type == EC_CURVE_TYPE_EDWARDS)
      {
         //Check the length of the public key
         if(length == ((curve->fieldSize / 8) + 1))
         {
            //Save elliptic curve parameters
            key->curve = curve;
            //Copy the public key
            osMemcpy(key->q, input, length);
         }
         else
         {
            //The length of the public key is not acceptable
            error = ERROR_INVALID_KEY_LENGTH;
         }
      }
      else
      {
         //Invalid elliptic curve
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
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
 * @brief Export an EdDSA public key
 * @param[in] key EdDSA public key
 * @param[out] output Pointer to the octet string (optional parameter)
 * @param[out] written Length of the resulting octet string, in bytes
 * @return Error code
 **/

error_t eddsaExportPublicKey(const EddsaPublicKey *key, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && written != NULL)
   {
      //Edwards elliptic curve?
      if(key->curve != NULL && key->curve->type == EC_CURVE_TYPE_EDWARDS)
      {
         //Determine the length of the public key
         n = (key->curve->fieldSize / 8) + 1;

         //If the output parameter is NULL, then the function calculates the
         //length of the octet string without copying any data
         if(output != NULL)
         {
            //Copy the public key
            osMemcpy(output, key->q, n);
         }

         //Length of the resulting octet string
         *written = n;
      }
      else
      {
         //Invalid elliptic curve
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
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
 * @brief Import an EdDSA private key
 * @param[out] key EdDSA private key
 * @param[in] curve Elliptic curve parameters
 * @param[in] data Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @return Error code
 **/

error_t eddsaImportPrivateKey(EddsaPrivateKey *key, const EcCurve *curve,
   const uint8_t *data, size_t length)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && curve != NULL && data != NULL)
   {
      //Edwards elliptic curve?
      if(curve->type == EC_CURVE_TYPE_EDWARDS)
      {
         //Check the length of the private key
         if(length == ((curve->fieldSize / 8) + 1))
         {
            //Save elliptic curve parameters
            key->curve = curve;
            //Copy the private key
            osMemcpy(key->d, data, length);
         }
         else
         {
            //The length of the public key is not acceptable
            error = ERROR_INVALID_KEY_LENGTH;
         }
      }
      else
      {
         //Invalid elliptic curve
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
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
 * @brief Export an EdDSA private key
 * @param[in] key EdDSA private key
 * @param[out] output Pointer to the octet string (optional parameter)
 * @param[out] written Length of the octet string, in bytes
 * @return Error code
 **/

error_t eddsaExportPrivateKey(const EddsaPrivateKey *key, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && written != NULL)
   {
      //Edwards elliptic curve?
      if(key->curve != NULL && key->curve->type == EC_CURVE_TYPE_EDWARDS)
      {
         //Determine the length of the private key
         n = (key->curve->fieldSize / 8) + 1;

         //If the output parameter is NULL, then the function calculates the
         //length of the octet string without copying any data
         if(output != NULL)
         {
            //Copy the private key
            osMemcpy(output, key->d, n);
         }

         //Length of the resulting octet string
         *written = n;
      }
      else
      {
         //Invalid elliptic curve
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
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

#endif
