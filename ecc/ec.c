/**
 * @file ec.c
 * @brief ECC (Elliptic Curve Cryptography)
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
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (EC_SUPPORT == ENABLED)

//EC Public Key OID (1.2.840.10045.2.1)
const uint8_t EC_PUBLIC_KEY_OID[7] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};


/**
 * @brief Initialize an EC public key
 * @param[in] key Pointer to the EC public key to initialize
 **/

void ecInitPublicKey(EcPublicKey *key)
{
   //Initialize elliptic curve parameters
   key->curve = NULL;

   //Initialize public key
   ecScalarSetInt(key->q.x, 0, EC_MAX_MODULUS_SIZE);
   ecScalarSetInt(key->q.y, 0, EC_MAX_MODULUS_SIZE);
}


/**
 * @brief Release an EC public key
 * @param[in] key Pointer to the EC public key to free
 **/

void ecFreePublicKey(EcPublicKey *key)
{
   //Clear public key
   osMemset(key, 0, sizeof(EcPublicKey));
}


/**
 * @brief Initialize an EC private key
 * @param[in] key Pointer to the EC private key to initialize
 **/

void ecInitPrivateKey(EcPrivateKey *key)
{
   //Initialize elliptic curve parameters
   key->curve = NULL;

   //Initialize private key
   ecScalarSetInt(key->d, 0, EC_MAX_ORDER_SIZE);
   //Initialize private key slot
   key->slot = -1;

   //Initialize public key
   ecInitPublicKey(&key->q);
}


/**
 * @brief Release an EC private key
 * @param[in] key Pointer to the EC public key to free
 **/

void ecFreePrivateKey(EcPrivateKey *key)
{
   //Clear private key
   osMemset(key, 0, sizeof(EcPrivateKey));
}


/**
 * @brief EC key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] curve Elliptic curve parameters
 * @param[out] privateKey EC private key
 * @param[out] publicKey EC public key (optional parameter)
 * @return Error code
 **/

__weak_func error_t ecGenerateKeyPair(const PrngAlgo *prngAlgo,
   void *prngContext, const EcCurve *curve, EcPrivateKey *privateKey,
   EcPublicKey *publicKey)
{
   error_t error;

   //Generate a private key
   error = ecGeneratePrivateKey(prngAlgo, prngContext, curve, privateKey);

   //Check status code
   if(!error)
   {
      //Derive the public key from the private key
      error = ecGeneratePublicKey(privateKey, &privateKey->q);
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
 * @brief EC private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] curve Elliptic curve parameters
 * @param[out] privateKey EC private key
 * @return Error code
 **/

error_t ecGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EcPrivateKey *privateKey)
{
   error_t error;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL || curve == NULL ||
      privateKey == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Save elliptic curve parameters
   privateKey->curve = curve;

   //Initialize private key
   ecScalarSetInt(privateKey->d, 0, EC_MAX_ORDER_SIZE);
   //Initialize public key
   ecInitPublicKey(&privateKey->q);

   //Generate a random number d such as 0 < d < q - 1
   error = ecScalarRand(curve, privateKey->d, prngAlgo, prngContext);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Private key:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", privateKey->d, (curve->orderSize + 31) / 32);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Derive the public key from an EC private key
 * @param[in] privateKey EC private key
 * @param[out] publicKey EC public key
 * @return Error code
 **/

error_t ecGeneratePublicKey(const EcPrivateKey *privateKey,
   EcPublicKey *publicKey)
{
   error_t error;
   uint_t pLen;
   EcPoint3 q;

   //Check parameters
   if(privateKey == NULL || publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get the length of the modulus, in words
   pLen = (privateKey->curve->fieldSize + 31) / 32;

   //Save elliptic curve parameters
   publicKey->curve = privateKey->curve;

   //Initialize EC public key
   ecScalarSetInt(publicKey->q.x, 0, EC_MAX_MODULUS_SIZE);
   ecScalarSetInt(publicKey->q.y, 0, EC_MAX_MODULUS_SIZE);

   //Compute Q = d.G
   error = ecMulRegular(publicKey->curve, &q, privateKey->d,
      &publicKey->curve->g);
   //Any error to report?
   if(error)
      return error;

   //Convert the public key to affine representation
   error = ecAffinify(publicKey->curve, &q, &q);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting EC public key
   ecScalarCopy(publicKey->q.x, q.x, pLen);
   ecScalarCopy(publicKey->q.y, q.y, pLen);

   //Debug message
   TRACE_DEBUG("  Public key X:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", publicKey->q.x, pLen);
   TRACE_DEBUG("  Public key Y:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", publicKey->q.y, pLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import an EC public key
 * @param[out] key EC public key
 * @param[in] curve Elliptic curve parameters
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @param[in] format EC public key format (X9.63 or raw format)
 * @return Error code
 **/

error_t ecImportPublicKey(EcPublicKey *key, const EcCurve *curve,
   const uint8_t *input, size_t length, EcPublicKeyFormat format)
{
   error_t error;
   size_t n;

   //Check parameters
   if(key != NULL && curve != NULL && input != NULL)
   {
      //Check curve type
      if(curve->type == EC_CURVE_TYPE_WEIERSTRASS ||
         curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0 ||
         curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
      {
         //Get the length of the modulus, in bytes
         n = (curve->fieldSize + 7) / 8;

         //Check the format of the public key
         if(format == EC_PUBLIC_KEY_FORMAT_X963)
         {
            //Read the public key
            error = ecImportPoint(curve, &key->q, input, length);
         }
         else if(format == EC_PUBLIC_KEY_FORMAT_RAW)
         {
            //Check the length of the octet string
            if(length == (n * 2))
            {
               //Convert the x-coordinate to an integer
               error = ecScalarImport(key->q.x, EC_MAX_MODULUS_SIZE, input,
                  n, EC_SCALAR_FORMAT_BIG_ENDIAN);

               //Check status code
               if(!error)
               {
                  //Convert the y-coordinate to an integer
                  error = ecScalarImport(key->q.y, EC_MAX_MODULUS_SIZE,
                     input + n, n, EC_SCALAR_FORMAT_BIG_ENDIAN);
               }
            }
            else
            {
               //The length of the octet string is not acceptable
               error = ERROR_INVALID_LENGTH;
            }
         }
         else if(format == EC_PUBLIC_KEY_FORMAT_RAW_X)
         {
            //Convert the x-coordinate to an integer
            error = ecScalarImport(key->q.x, EC_MAX_MODULUS_SIZE, input,
               length, EC_SCALAR_FORMAT_BIG_ENDIAN);
         }
         else if(format == EC_PUBLIC_KEY_FORMAT_RAW_Y)
         {
            //Convert the y-coordinate to an integer
            error = ecScalarImport(key->q.y, EC_MAX_MODULUS_SIZE, input,
               length, EC_SCALAR_FORMAT_BIG_ENDIAN);
         }
         else
         {
            //Invalid format
            error = ERROR_INVALID_PARAMETER;
         }
      }
      else if(curve->type == EC_CURVE_TYPE_MONTGOMERY)
      {
         //Check the length of the octet string
         if(length == ((curve->fieldSize + 7) / 8))
         {
            //Clear unused coordinate
            ecScalarSetInt(key->q.y, 0, EC_MAX_MODULUS_SIZE);

            //Convert the u-coordinate to an integer
            error = ecScalarImport(key->q.x, EC_MAX_MODULUS_SIZE, input,
               length, EC_SCALAR_FORMAT_LITTLE_ENDIAN);
         }
         else
         {
            //Report an error
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
      else
      {
         //Report an error
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
      }

      //Check status code
      if(!error)
      {
         //Save elliptic curve parameters
         key->curve = curve;
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
 * @brief Export an EC public key
 * @param[in] key EC public key
 * @param[out] output Pointer to the octet string
 * @param[out] written Length of the octet string, in bytes
 * @param[in] format EC public key format (X9.63 or raw format)
 * @return Error code
 **/

error_t ecExportPublicKey(const EcPublicKey *key, uint8_t *output,
   size_t *written, EcPublicKeyFormat format)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && written != NULL)
   {
      //Valid elliptic curve?
      if(key->curve != NULL)
      {
         //Check curve type
         if(key->curve->type == EC_CURVE_TYPE_WEIERSTRASS ||
            key->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0 ||
            key->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
         {
            //Get the length of the modulus, in bytes
            n = (key->curve->fieldSize + 7) / 8;

            //Check the format of the public key
            if(format == EC_PUBLIC_KEY_FORMAT_X963)
            {
               //Write the public key
               error = ecExportPoint(key->curve, &key->q, output, &n);
            }
            else if(format == EC_PUBLIC_KEY_FORMAT_RAW)
            {
               //If the output parameter is NULL, then the function calculates
               //the length of the octet string without copying any data
               if(output != NULL)
               {
                  //Convert the x-coordinate to an octet string
                  error = ecScalarExport(key->q.x, (n + 3) / 4, output, n,
                     EC_SCALAR_FORMAT_BIG_ENDIAN);

                  //Check status code
                  if(!error)
                  {
                     //Convert the y-coordinate to an octet string
                     error = ecScalarExport(key->q.y, (n + 3) / 4, output + n, n,
                        EC_SCALAR_FORMAT_BIG_ENDIAN);
                  }
               }

               //Check status code
               if(!error)
               {
                  //Length of the resulting octet string
                  n = 2 * n;
               }
            }
            else if(format == EC_PUBLIC_KEY_FORMAT_RAW_X)
            {
               //If the output parameter is NULL, then the function calculates
               //the length of the octet string without copying any data
               if(output != NULL)
               {
                  //Convert the x-coordinate to an octet string
                  error = ecScalarExport(key->q.x, (n + 3) / 4, output, n,
                     EC_SCALAR_FORMAT_BIG_ENDIAN);
               }
            }
            else if(format == EC_PUBLIC_KEY_FORMAT_RAW_Y)
            {
               //If the output parameter is NULL, then the function calculates
               //the length of the octet string without copying any data
               if(output != NULL)
               {
                  //Convert the y-coordinate to an octet string
                  error = ecScalarExport(key->q.y, (n + 3) / 4, output, n,
                     EC_SCALAR_FORMAT_BIG_ENDIAN);
               }
            }
            else
            {
               //Invalid format
               error = ERROR_INVALID_PARAMETER;
            }
         }
         else if(key->curve->type == EC_CURVE_TYPE_MONTGOMERY)
         {
            //Get the length of the modulus, in bytes
            n = (key->curve->fieldSize + 7) / 8;

            //If the output parameter is NULL, then the function calculates the
            //length of the octet string without copying any data
            if(output != NULL)
            {
               //Convert the u-coordinate to an octet string
               error = ecScalarExport(key->q.x, (n + 3) / 4, output, n,
                  EC_SCALAR_FORMAT_LITTLE_ENDIAN);
            }
         }
         else
         {
            //Report an error
            error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
         }
      }
      else
      {
         //Invalid elliptic curve
         error = ERROR_INVALID_ELLIPTIC_CURVE;
      }

      //Check status code
      if(!error)
      {
         //Return the length of the octet string
         *written = n;
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
 * @brief Import an EC private key
 * @param[out] key EC private key
 * @param[in] curve Elliptic curve parameters
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @return Error code
 **/

error_t ecImportPrivateKey(EcPrivateKey *key, const EcCurve *curve,
   const uint8_t *input, size_t length)
{
   error_t error;

   //Check parameters
   if(key != NULL && curve != NULL && input != NULL)
   {
      //Check curve type
      if(curve->type == EC_CURVE_TYPE_WEIERSTRASS ||
         curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0 ||
         curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
      {
         //Read the private key
         error = ecScalarImport(key->d, EC_MAX_ORDER_SIZE, input, length,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
      }
      else if(curve->type == EC_CURVE_TYPE_MONTGOMERY)
      {
         //Check the length of the octet string
         if(length == ((curve->orderSize + 7) / 8))
         {
            //Read the private key
            error = ecScalarImport(key->d, EC_MAX_ORDER_SIZE, input, length,
               EC_SCALAR_FORMAT_LITTLE_ENDIAN);
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY_LENGTH;
         }
      }
      else
      {
         //Report an error
         error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
      }

      //Check status code
      if(!error)
      {
         //Save elliptic curve parameters
         key->curve = curve;
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
 * @brief Export an EC private key
 * @param[in] key EC private key
 * @param[out] output Pointer to the octet string
 * @param[out] written Length of the octet string, in bytes
 * @return Error code
 **/

error_t ecExportPrivateKey(const EcPrivateKey *key, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check parameters
   if(key != NULL && written != NULL)
   {
      //Valid elliptic curve?
      if(key->curve != NULL)
      {
         //Check curve type
         if(key->curve->type == EC_CURVE_TYPE_WEIERSTRASS ||
            key->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0 ||
            key->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
         {
            //Get the length of the order, in bytes
            n = (key->curve->orderSize + 7) / 8;

            //If the output parameter is NULL, then the function calculates the
            //length of the octet string without copying any data
            if(output != NULL)
            {
               //Write the private key
               error = ecScalarExport(key->d, (n + 3) / 4, output, n,
                  EC_SCALAR_FORMAT_BIG_ENDIAN);
            }
         }
         else if(key->curve->type == EC_CURVE_TYPE_MONTGOMERY)
         {
            //Get the length of the order, in bytes
            n = (key->curve->orderSize + 7) / 8;

            //If the output parameter is NULL, then the function calculates the
            //length of the octet string without copying any data
            if(output != NULL)
            {
               //Write the private key
               error = ecScalarExport(key->d, (n + 3) / 4, output, n,
                  EC_SCALAR_FORMAT_LITTLE_ENDIAN);
            }
         }
         else
         {
            //Report an error
            error = ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
         }
      }
      else
      {
         //Invalid elliptic curve
         error = ERROR_INVALID_ELLIPTIC_CURVE;
      }

      //Check status code
      if(!error)
      {
         //Return the length of the octet string
         *written = n;
      }
   }
   else
   {
      //Invalid elliptic curve
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Convert an octet string to an EC point
 * @param[in] curve Elliptic curve parameters
 * @param[out] r EC point resulting from the conversion
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string
 * @return Error code
 **/

error_t ecImportPoint(const EcCurve *curve, EcPoint *r, const uint8_t *input,
   size_t length)
{
   error_t error;
   size_t n;

   //Check parameters
   if(curve == NULL || r == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get the length of the modulus, in bytes
   n = (curve->fieldSize + 7) / 8;

   //Check the length of the octet string
   if(length != (n * 2 + 1))
      return ERROR_ILLEGAL_PARAMETER;

   //Compressed point representation is not supported
   if(input[0] != EC_POINT_FORMAT_UNCOMPRESSED)
      return ERROR_ILLEGAL_PARAMETER;

   //Convert the x-coordinate to an integer
   error = ecScalarImport(r->x, EC_MAX_MODULUS_SIZE, input + 1, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Convert the y-coordinate to an integer
   error = ecScalarImport(r->y, EC_MAX_MODULUS_SIZE, input + n + 1, n,
      EC_SCALAR_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Convert an EC point to an octet string
 * @param[in] curve Elliptic curve parameters
 * @param[in] a EC point to be converted
 * @param[out] output Pointer to the octet string
 * @param[out] written Length of the resulting octet string
 * @return Error code
 **/

error_t ecExportPoint(const EcCurve *curve, const EcPoint *a, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(curve == NULL || a == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get the length of the modulus, in bytes
   n = (curve->fieldSize + 7) / 8;

   //If the output parameter is NULL, then the function calculates the length
   //of the octet string without copying any data
   if(output != NULL)
   {
      //Point compression is not used
      output[0] = EC_POINT_FORMAT_UNCOMPRESSED;

      //Convert the x-coordinate to an octet string
      error = ecScalarExport(a->x, (n + 3) / 4, output + 1, n,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         return error;

      //Convert the y-coordinate to an octet string
      error = ecScalarExport(a->y, (n + 3) / 4, output + n + 1, n,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         return error;
   }

   //Return the length of the octet string
   *written = n * 2 + 1;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute projective representation
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Projective representation of the point
 * @param[in] s Affine representation of the point
 **/

void ecProjectify(const EcCurve *curve, EcPoint3 *r, const EcPoint *s)
{
   uint_t i;
   uint_t pLen;

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Copy x, y and z-coordinates
   for(i = 0; i < pLen; i++)
   {
      r->x[i] = s->x[i];
      r->y[i] = s->y[i];
      r->z[i] = 0;
   }

   //Map the point to projective space
   r->z[0] = 1;
}


/**
 * @brief Recover affine representation
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Affine representation of the point
 * @param[in] s Projective representation of the point
 * @return Error code
 **/

__weak_func error_t ecAffinify(const EcCurve *curve, EcPoint3 *r,
   const EcPoint3 *s)
{
   error_t error;
   uint_t pLen;
   uint32_t a[EC_MAX_MODULUS_SIZE];
   uint32_t b[EC_MAX_MODULUS_SIZE];

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Point at the infinity?
   if(ecScalarTestEqualInt(s->z, 0, pLen))
   {
      //The point at the infinity has no affine representation
      error = ERROR_INVALID_PARAMETER;
   }
   else
   {
      //Compute a = 1/Sz mod p
      ecFieldInvMod(curve, a, s->z);

      //Set Rx = a^2 * Sx mod p
      ecFieldSqrMod(curve, b, a);
      ecFieldMulMod(curve, r->x, b, s->x);

      //Set Ry = a^3 * Sy mod p
      ecFieldMulMod(curve, b, b, a);
      ecFieldMulMod(curve, r->y, b, s->y);

      //Set Rz = 1
      ecScalarSetInt(r->z, 1, pLen);

      //Successful processing
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether the affine point S is on the curve
 * @param[in] curve Elliptic curve parameters
 * @param[in] s Affine representation of the point
 * @return TRUE if the affine point S is on the curve, else FALSE
 **/

__weak_func bool_t ecIsPointAffine(const EcCurve *curve, const EcPoint *s)
{
   uint_t pLen;
   bool_t valid;
   uint32_t t1[EC_MAX_MODULUS_SIZE];
   uint32_t t2[EC_MAX_MODULUS_SIZE];

   //Initialize flag
   valid = FALSE;

   //Check parameters
   if(curve != NULL && s != NULL)
   {
      //Verify that 0 <= Sx < p and 0 <= Sy < p
      if(ecScalarComp(s->x, curve->p, EC_MAX_MODULUS_SIZE) < 0 &&
         ecScalarComp(s->y, curve->p, EC_MAX_MODULUS_SIZE) < 0)
      {
         //Get the length of the modulus, in words
         pLen = (curve->fieldSize + 31) / 32;

         //Compute t1 = (Sx^3 + a * Sx + b) mod p
         ecFieldSqrMod(curve, t1, s->x);
         ecFieldMulMod(curve, t1, t1, s->x);
         ecFieldMulMod(curve, t2, curve->a, s->x);
         ecFieldAddMod(curve, t1, t1, t2);
         ecFieldAddMod(curve, t1, t1, curve->b);

         //Compute t2 = Sy^2
         ecFieldSqrMod(curve, t2, s->y);

         //Check whether the point is on the elliptic curve
         if(ecScalarComp(t1, t2, pLen) == 0)
         {
            valid = TRUE;
         }
      }
   }

   //Return TRUE if the affine point S is on the curve
   return valid;
}


/**
 * @brief Point doubling
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = 2S
 * @param[in] s Point S
 **/

void ecDouble(EcState *state, EcPoint3 *r, const EcPoint3 *s)
{
   uint_t pLen;

   //Get the length of the modulus, in words
   pLen = (state->curve->fieldSize + 31) / 32;

   //Set t1 = Sx
   ecScalarCopy(state->t1, s->x, pLen);
   //Set t2 = Sy
   ecScalarCopy(state->t2, s->y, pLen);
   //Set t3 = Sz
   ecScalarCopy(state->t3, s->z, pLen);

   //Point at the infinity?
   if(ecScalarTestEqualInt(state->t3, 0, pLen))
   {
      //Set R = (1, 1, 0)
      ecScalarSetInt(r->x, 1, pLen);
      ecScalarSetInt(r->y, 1, pLen);
      ecScalarSetInt(r->z, 0, pLen);
   }
   else
   {
      //Check curve type
      if(state->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A0)
      {
         //Compute t5 = t1^2
         ecFieldSqrMod(state->curve, state->t5, state->t1);
         //Compute t4 = 3 * t5
         ecFieldAddMod(state->curve, state->t4, state->t5, state->t5);
         ecFieldAddMod(state->curve, state->t4, state->t4, state->t5);
      }
      else if(state->curve->type == EC_CURVE_TYPE_WEIERSTRASS_A3)
      {
         //Compute t4 = t3^2
         ecFieldSqrMod(state->curve, state->t4, state->t3);
         //Compute t5 = t1 - t4
         ecFieldSubMod(state->curve, state->t5, state->t1, state->t4);
         //Compute t4 = t1 + t4
         ecFieldAddMod(state->curve, state->t4, state->t1, state->t4);
         //Compute t5 = t4 * t5
         ecFieldMulMod(state->curve, state->t5, state->t4, state->t5);
         //Compute t4 = 3 * t5
         ecFieldAddMod(state->curve, state->t4, state->t5, state->t5);
         ecFieldAddMod(state->curve, state->t4, state->t4, state->t5);
      }
      else
      {
         //Compute t4 = t3^4
         ecFieldSqrMod(state->curve, state->t4, state->t3);
         ecFieldSqrMod(state->curve, state->t4, state->t4);
         //Compute t4 = a * t4
         ecFieldMulMod(state->curve, state->t4, state->t4, state->curve->a);
         //Compute t5 = t1^2
         ecFieldSqrMod(state->curve, state->t5, state->t1);
         //Compute t4 = t4 + 3 * t5
         ecFieldAddMod(state->curve, state->t4, state->t4, state->t5);
         ecFieldAddMod(state->curve, state->t4, state->t4, state->t5);
         ecFieldAddMod(state->curve, state->t4, state->t4, state->t5);
      }

      //Compute t3 = t3 * t2
      ecFieldMulMod(state->curve, state->t3, state->t3, state->t2);
      //Compute t3 = 2 * t3
      ecFieldAddMod(state->curve, state->t3, state->t3, state->t3);
      //Compute t2 = t2^2
      ecFieldSqrMod(state->curve, state->t2, state->t2);
      //Compute t5 = t1 * t2
      ecFieldMulMod(state->curve, state->t5, state->t1, state->t2);
      //Compute t5 = 4 * t5
      ecFieldAddMod(state->curve, state->t5, state->t5, state->t5);
      ecFieldAddMod(state->curve, state->t5, state->t5, state->t5);
      //Compute t1 = t4^2
      ecFieldSqrMod(state->curve, state->t1, state->t4);
      //Compute t1 = t1 - 2 * t5
      ecFieldSubMod(state->curve, state->t1, state->t1, state->t5);
      ecFieldSubMod(state->curve, state->t1, state->t1, state->t5);
      //Compute t2 = t2^2
      ecFieldSqrMod(state->curve, state->t2, state->t2);
      //Compute t2 = 8 * t2
      ecFieldAddMod(state->curve, state->t2, state->t2, state->t2);
      ecFieldAddMod(state->curve, state->t2, state->t2, state->t2);
      ecFieldAddMod(state->curve, state->t2, state->t2, state->t2);
      //Compute t5 = t5 - t1
      ecFieldSubMod(state->curve, state->t5, state->t5, state->t1);
      //Compute t5 = t4 * t5
      ecFieldMulMod(state->curve, state->t5, state->t4, state->t5);
      //Compute t2 = t5 - t2
      ecFieldSubMod(state->curve, state->t2, state->t5, state->t2);

      //Set Rx = t1
      ecScalarCopy(r->x, state->t1, pLen);
      //Set Ry = t2
      ecScalarCopy(r->y, state->t2, pLen);
      //Set Rz = t3
      ecScalarCopy(r->z, state->t3, pLen);
   }
}


/**
 * @brief Point addition (helper routine)
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = S + T
 * @param[in] s First operand
 * @param[in] t Second operand
 **/

void ecAdd(EcState *state, EcPoint3 *r, const EcPoint3 *s,
   const EcPoint3 *t)
{
   uint_t pLen;
   uint32_t c;

   //Get the length of the modulus, in words
   pLen = (state->curve->fieldSize + 31) / 32;

   //Set t1 = Sx
   ecScalarCopy(state->t1, s->x, pLen);
   //Set t2 = Sy
   ecScalarCopy(state->t2, s->y, pLen);
   //Set t3 = Sz
   ecScalarCopy(state->t3, s->z, pLen);
   //Set t4 = Tx
   ecScalarCopy(state->t4, t->x, pLen);
   //Set t5 = Ty
   ecScalarCopy(state->t5, t->y, pLen);

   //Check whether Tz != 1
   if(ecScalarTestNotEqualInt(t->z, 1, pLen))
   {
      //Compute t6 = Tz
      ecScalarCopy(state->t6, t->z, pLen);
      //Compute t7 = t6^2
      ecFieldSqrMod(state->curve, state->t7, state->t6);
      //Compute t1 = t1 * t7
      ecFieldMulMod(state->curve, state->t1, state->t1, state->t7);
      //Compute t7 = t6 * t7
      ecFieldMulMod(state->curve, state->t7, state->t6, state->t7);
      //Compute t2 = t2 * t7
      ecFieldMulMod(state->curve, state->t2, state->t2, state->t7);
   }

   //Compute t7 = t3^2
   ecFieldSqrMod(state->curve, state->t7, state->t3);
   //Compute t4 = t4 * t7
   ecFieldMulMod(state->curve, state->t4, state->t4, state->t7);
   //Compute t7 = t3 * t7
   ecFieldMulMod(state->curve, state->t7, state->t3, state->t7);
   //Compute t5 = t5 * t7
   ecFieldMulMod(state->curve, state->t5, state->t5, state->t7);
   //Compute t4 = t1 - t4
   ecFieldSubMod(state->curve, state->t4, state->t1, state->t4);
   //Compute t5 = t2 - t5
   ecFieldSubMod(state->curve, state->t5, state->t2, state->t5);

   //Check whether t4 == 0
   if(ecScalarTestEqualInt(state->t4, 0, pLen))
   {
      //Check whether t5 == 0
      if(ecScalarTestEqualInt(state->t5, 0, pLen))
      {
         //Set R = (0, 0, 0)
         ecScalarSetInt(r->x, 0, pLen);
         ecScalarSetInt(r->y, 0, pLen);
         ecScalarSetInt(r->z, 0, pLen);
      }
      else
      {
         //Set R = (1, 1, 0)
         ecScalarSetInt(r->x, 1, pLen);
         ecScalarSetInt(r->y, 1, pLen);
         ecScalarSetInt(r->z, 0, pLen);
      }
   }
   else
   {
      //Compute t1 = 2 * t1 - t4
      ecFieldAddMod(state->curve, state->t1, state->t1, state->t1);
      ecFieldSubMod(state->curve, state->t1, state->t1, state->t4);
      //Compute t2 = 2 * t2 - t5
      ecFieldAddMod(state->curve, state->t2, state->t2, state->t2);
      ecFieldSubMod(state->curve, state->t2, state->t2, state->t5);

      //Check whether Tz != 1
      if(ecScalarTestNotEqualInt(t->z, 1, pLen))
      {
         //Compute t3 = t3 * t6
         ecFieldMulMod(state->curve, state->t3, state->t3, state->t6);
      }

      //Compute t3 = t3 * t4
      ecFieldMulMod(state->curve, state->t3, state->t3, state->t4);
      //Compute t7 = t4^2
      ecFieldSqrMod(state->curve, state->t7, state->t4);
      //Compute t4 = t4 * t7
      ecFieldMulMod(state->curve, state->t4, state->t4, state->t7);
      //Compute t7 = t1 * t7
      ecFieldMulMod(state->curve, state->t7, state->t1, state->t7);
      //Compute t1 = t5^2
      ecFieldSqrMod(state->curve, state->t1, state->t5);
      //Compute t1 = t1 - t7
      ecFieldSubMod(state->curve, state->t1, state->t1, state->t7);
      //Compute t7 = t7 - 2 * t1
      ecFieldAddMod(state->curve, state->t6, state->t1, state->t1);
      ecFieldSubMod(state->curve, state->t7, state->t7, state->t6);
      //Compute t5 = t5 * t7
      ecFieldMulMod(state->curve, state->t5, state->t5, state->t7);
      //Compute t4 = t2 * t4
      ecFieldMulMod(state->curve, state->t4, state->t2, state->t4);
      //Compute t2 = t5 - t4
      ecFieldSubMod(state->curve, state->t2, state->t5, state->t4);

      //Compute t2 = t2 / 2
      if(ecScalarGetBitValue(state->t2, 0) == 0)
      {
         //Perform a right shift operation
         ecScalarShiftRight(state->t2, state->t2, 1, pLen);
      }
      else
      {
         //First add p, then perform a right shift operation
         c = ecScalarAdd(state->t2, state->t2, state->curve->p, pLen);
         ecScalarShiftRight(state->t2, state->t2, 1, pLen);
         state->t2[pLen - 1] |= c << 31;
      }

      //Set Rx = t1
      ecScalarCopy(r->x, state->t1, pLen);
      //Set Ry = t2
      ecScalarCopy(r->y, state->t2, pLen);
      //Set Rz = t3
      ecScalarCopy(r->z, state->t3, pLen);
   }
}


/**
 * @brief Point addition
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = S + T
 * @param[in] s First operand
 * @param[in] t Second operand
 **/

void ecFullAdd(EcState *state, EcPoint3 *r,
   const EcPoint3 *s, const EcPoint3 *t)
{
   uint_t pLen;
   EcPoint3 u;

   //Get the length of the modulus, in words
   pLen = (state->curve->fieldSize + 31) / 32;

   //Check whether Sz == 0
   if(ecScalarTestEqualInt(s->z, 0, pLen))
   {
      //Set R = T
      ecScalarCopy(r->x, t->x, pLen);
      ecScalarCopy(r->y, t->y, pLen);
      ecScalarCopy(r->z, t->z, pLen);
   }
   //Check whether Tz == 0
   else if(ecScalarTestEqualInt(t->z, 0, pLen))
   {
      //Set R = S
      ecScalarCopy(r->x, s->x, pLen);
      ecScalarCopy(r->y, s->y, pLen);
      ecScalarCopy(r->z, s->z, pLen);
   }
   else
   {
      //Compute U = S + T
      ecAdd(state, &u, s, t);

      //Check whether U == (0, 0, 0)
      if(ecScalarTestEqualInt(u.x, 0, pLen) &&
         ecScalarTestEqualInt(u.y, 0, pLen) &&
         ecScalarTestEqualInt(u.z, 0, pLen))
      {
         //Compute R = 2 * S
         ecDouble(state, r, s);
      }
      else
      {
         //Set R = U
         ecScalarCopy(r->x, u.x, pLen);
         ecScalarCopy(r->y, u.y, pLen);
         ecScalarCopy(r->z, u.z, pLen);
      }
   }
}


/**
 * @brief Point subtraction
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = S - T
 * @param[in] s First operand
 * @param[in] t Second operand
 **/

void ecFullSub(EcState *state, EcPoint3 *r, const EcPoint3 *s,
   const EcPoint3 *t)
{
   uint_t pLen;
   EcPoint3 u;

   //Get the length of the modulus, in words
   pLen = (state->curve->fieldSize + 31) / 32;

   //Set Ux = Tx and Uz = Tz
   ecScalarCopy(u.x, t->x, pLen);
   ecScalarCopy(u.z, t->z, pLen);

   //Set Uy = p - Ty
   ecScalarSub(u.y, state->curve->p, t->y, pLen);

   //Compute R = S + U
   ecFullAdd(state, r, s, &u);
}


/**
 * @brief Scalar multiplication (fast calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < q
 * @param[in] s EC point
 * @return Error code
 **/

__weak_func error_t ecMulFast(const EcCurve *curve, EcPoint3 *r,
   const uint32_t *d, const EcPoint3 *s)
{
   uint_t i;
   uint_t pLen;
   uint_t qLen;
   uint32_t k[EC_MAX_ORDER_SIZE + 1];
   uint32_t h[EC_MAX_ORDER_SIZE + 1];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   EcMulFastState *state;
#else
   EcMulFastState state[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(EcMulFastState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(EcMulFastState));
   //Save elliptic curve parameters
   state->subState.curve = curve;

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   qLen = (curve->orderSize + 31) / 32;

   //Check whether d == 0
   if(ecScalarTestEqualInt(d, 0, pLen))
   {
      //Set R = (1, 1, 0)
      ecScalarSetInt(r->x, 1, pLen);
      ecScalarSetInt(r->y, 1, pLen);
      ecScalarSetInt(r->z, 0, pLen);
   }
   //Check whether d == 1
   else if(ecScalarTestEqualInt(d, 1, pLen))
   {
      //Set R = S
      ecScalarCopy(r->x, s->x, pLen);
      ecScalarCopy(r->y, s->y, pLen);
      ecScalarCopy(r->z, s->z, pLen);
   }
   //Check whether Sz == 0
   else if(ecScalarTestEqualInt(s->z, 0, pLen))
   {
      //Set R = (1, 1, 0)
      ecScalarSetInt(r->x, 1, pLen);
      ecScalarSetInt(r->y, 1, pLen);
      ecScalarSetInt(r->z, 0, pLen);
   }
   else
   {
      //Check whether Sz != 1
      if(ecScalarTestNotEqualInt(s->z, 1, pLen))
      {
         //Normalize S
         ecAffinify(curve, r, s);
      }
      else
      {
         //Set R = S
         ecScalarCopy(r->x, s->x, pLen);
         ecScalarCopy(r->y, s->y, pLen);
         ecScalarCopy(r->z, s->z, pLen);
      }

      //Let k = d
      ecScalarCopy(k, d, qLen);
      k[qLen] = 0;

      //Precompute h = 3 * d
      ecScalarAdd(h, k, k, qLen + 1);
      ecScalarAdd(h, h, k, qLen + 1);

      //Calculate the length of h, in bits
      pLen = ecScalarGetBitLength(h, qLen + 1);

      //Scalar multiplication
      for(i = pLen - 2; i >= 1; i--)
      {
         //Point doubling
         ecDouble(&state->subState, r, r);

         //Check the values of h(i) and k(i)
         if(ecScalarGetBitValue(h, i) != 0 &&
            ecScalarGetBitValue(k, i) == 0)
         {
            //If h(i) == 1 and k(i) == 0, then compute R = R + S
            ecFullAdd(&state->subState, r, r, s);
         }
         else if(ecScalarGetBitValue(h, i) == 0 &&
            ecScalarGetBitValue(k, i) != 0)
         {
            //If h(i) == 0 and k(i) == 1, then compute R = R - S
            ecFullSub(&state->subState, r, r, s);
         }
         else
         {
            //Just for sanity
         }
      }
   }

   //Erase working state
   osMemset(state, 0, sizeof(EcMulFastState));

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release working state
   cryptoFreeMem(state);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Scalar multiplication (regular calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < q
 * @param[in] s EC point
 * @return Error code
 **/

__weak_func error_t ecMulRegular(const EcCurve *curve, EcPoint3 *r,
   const uint32_t *d, const EcPoint3 *s)
{
   int_t i;
   int_t pLen;
   uint32_t b;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   EcMulRegularState *state;
#else
   EcMulRegularState state[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(EcMulRegularState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(EcMulRegularState));
   //Save elliptic curve parameters
   state->subState.curve = curve;

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Initialize the value of the flag
   state->init = ecScalarGetBitValue(d, curve->orderSize - 1);

   //Compute (P0, Q0) = DBLU(S)
   ecDblu(&state->subState, &state->p0, &state->q0, s);

   //Set P = P0
   ecScalarCopy(state->p.x, state->p0.x, pLen);
   ecScalarCopy(state->p.y, state->p0.y, pLen);
   ecScalarCopy(state->p.z, state->p0.z, pLen);

   //Set Q = Q0
   ecScalarCopy(state->q.x, state->q0.x, pLen);
   ecScalarCopy(state->q.y, state->q0.y, pLen);
   ecScalarCopy(state->q.z, state->q0.z, pLen);

   //Montgomery ladder with co-Z addition formulae
   for(i = curve->orderSize - 2; i >= 0; i--)
   {
      //The scalar is processed in a left-to-right fashion
      b = ecScalarGetBitValue(d, i);

      //Conditional swap
      ecScalarSwap(state->p.x, state->q.x, b, pLen);
      ecScalarSwap(state->p.y, state->q.y, b, pLen);
      ecScalarSwap(state->p.z, state->q.z, b, pLen);

      //Compute (P, Q) = ZADDC(Q, P)
      ecZaddc(&state->subState, &state->p, &state->q, &state->q, &state->p);
      //Compute (Q, P) = ZADDU(P, Q)
      ecZaddu(&state->subState, &state->q, &state->p, &state->p, &state->q);

      //Conditional swap
      ecScalarSwap(state->p.x, state->q.x, b, pLen);
      ecScalarSwap(state->p.y, state->q.y, b, pLen);
      ecScalarSwap(state->p.z, state->q.z, b, pLen);

      //The loop does not depend on the length of the secret scalar
      ecScalarSelect(state->p.x, state->p0.x, state->p.x, state->init, pLen);
      ecScalarSelect(state->p.y, state->p0.y, state->p.y, state->init, pLen);
      ecScalarSelect(state->p.z, state->p0.z, state->p.z, state->init, pLen);
      ecScalarSelect(state->q.x, state->q0.x, state->q.x, state->init, pLen);
      ecScalarSelect(state->q.y, state->q0.y, state->q.y, state->init, pLen);
      ecScalarSelect(state->q.z, state->q0.z, state->q.z, state->init, pLen);

      //Update the value of flag
      state->init |= b;
   }

   //Copy resulting point
   ecScalarCopy(r->x, state->q.x, pLen);
   ecScalarCopy(r->y, state->q.y, pLen);
   ecScalarCopy(r->z, state->q.z, pLen);

   //Erase working state
   osMemset(state, 0, sizeof(EcMulRegularState));

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release working state
   cryptoFreeMem(state);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Twin multiplication
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d0.S + d1.T
 * @param[in] d0 An integer d such as 0 <= d0 < q
 * @param[in] s EC point
 * @param[in] d1 An integer d such as 0 <= d1 < q
 * @param[in] t EC point
 * @return Error code
 **/

__weak_func error_t ecTwinMul(const EcCurve *curve, EcPoint3 *r,
   const uint32_t *d0, const EcPoint3 *s, const uint32_t *d1,
   const EcPoint3 *t)
{
   int_t k;
   uint_t pLen;
   uint_t m;
   uint_t m0;
   uint_t m1;
   uint_t c0;
   uint_t c1;
   uint_t h0;
   uint_t h1;
   int_t u0;
   int_t u1;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   EcTwinMulState *state;
#else
   EcTwinMulState state[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(EcTwinMulState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(EcTwinMulState));
   //Save elliptic curve parameters
   state->subState.curve = curve;

   //Get the length of the modulus, in words
   pLen = (curve->fieldSize + 31) / 32;

   //Precompute SpT = S + T
   ecFullAdd(&state->subState, &state->spt, s, t);
   //Precompute SmT = S - T
   ecFullSub(&state->subState, &state->smt, s, t);

   //Let m0 be the bit length of d0
   m0 = ecScalarGetBitLength(d0, (curve->orderSize + 31) / 32);
   //Let m1 be the bit length of d1
   m1 = ecScalarGetBitLength(d1, (curve->orderSize + 31) / 32);
   //Let m = MAX(m0, m1)
   m = MAX(m0, m1);

   //Let c be a 2 x 6 binary matrix
   c0 = ecScalarGetBitValue(d0, m - 4);
   c0 |= ecScalarGetBitValue(d0, m - 3) << 1;
   c0 |= ecScalarGetBitValue(d0, m - 2) << 2;
   c0 |= ecScalarGetBitValue(d0, m - 1) << 3;
   c1 = ecScalarGetBitValue(d1, m - 4);
   c1 |= ecScalarGetBitValue(d1, m - 3) << 1;
   c1 |= ecScalarGetBitValue(d1, m - 2) << 2;
   c1 |= ecScalarGetBitValue(d1, m - 1) << 3;

   //Set R = (1, 1, 0)
   ecScalarSetInt(r->x, 1, pLen);
   ecScalarSetInt(r->y, 1, pLen);
   ecScalarSetInt(r->z, 0, pLen);

   //Calculate both multiplications at the same time
   for(k = m; k >= 0; k--)
   {
      //Compute h(0) = 16 * c(0,1) + 8 * c(0,2) + 4 * c(0,3) + 2 * c(0,4) + c(0,5)
      h0 = c0 & 0x1F;

      //Check whether c(0,0) == 1
      if(c0 & 0x20)
      {
         h0 = 31 - h0;
      }

      //Compute h(1) = 16 * c(1,1) + 8 * c(1,2) + 4 * c(1,3) + 2 * c(1,4) + c(1,5)
      h1 = c1 & 0x1F;

      //Check whether c(1,0) == 1
      if(c1 & 0x20)
      {
         h1 = 31 - h1;
      }

      //Compute u(0)
      if(h0 < ecTwinMulF(h1))
      {
         u0 = 0;
      }
      else if(c0 & 0x20)
      {
         u0 = -1;
      }
      else
      {
         u0 = 1;
      }

      //Compute u(1)
      if(h1 < ecTwinMulF(h0))
      {
         u1 = 0;
      }
      else if(c1 & 0x20)
      {
         u1 = -1;
      }
      else
      {
         u1 = 1;
      }

      //Update c matrix
      c0 <<= 1;
      c0 |= ecScalarGetBitValue(d0, k - 5);
      c0 ^= u0 ? 0x20 : 0x00;
      c1 <<= 1;
      c1 |= ecScalarGetBitValue(d1, k - 5);
      c1 ^= u1 ? 0x20 : 0x00;

      //Point doubling
      ecDouble(&state->subState, r, r);

      //Check u(0) and u(1)
      if(u0 == -1 && u1 == -1)
      {
         //Compute R = R - SpT
         ecFullSub(&state->subState, r, r, &state->spt);
      }
      else if(u0 == -1 && u1 == 0)
      {
         //Compute R = R - S
         ecFullSub(&state->subState, r, r, s);
      }
      else if(u0 == -1 && u1 == 1)
      {
         //Compute R = R - SmT
         ecFullSub(&state->subState, r, r, &state->smt);
      }
      else if(u0 == 0 && u1 == -1)
      {
         //Compute R = R - T
         ecFullSub(&state->subState, r, r, t);
      }
      else if(u0 == 0 && u1 == 1)
      {
         //Compute R = R + T
         ecFullAdd(&state->subState, r, r, t);
      }
      else if(u0 == 1 && u1 == -1)
      {
         //Compute R = R + SmT
         ecFullAdd(&state->subState, r, r, &state->smt);
      }
      else if(u0 == 1 && u1 == 0)
      {
         //Compute R = R + S
         ecFullAdd(&state->subState, r, r, s);
      }
      else if(u0 == 1 && u1 == 1)
      {
         //Compute R = R + SpT
         ecFullAdd(&state->subState, r, r, &state->spt);
      }
      else
      {
      }
   }

   //Erase working state
   osMemset(state, 0, sizeof(EcTwinMulState));

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release working state
   cryptoFreeMem(state);
#endif

   //Successful processing
   return NO_ERROR;
}

#endif
