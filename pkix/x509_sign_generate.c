/**
 * @file x509_sign_generate.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation
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
#include "pkix/x509_sign_generate.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)

//Signature generation/verification callback functions
#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   static X509SignGenCallback x509SignGenCallback = NULL;
#endif


/**
 * @brief Register signature generation callback function
 * @param[in] callback Signature generation callback function
 * @return Error code
 **/

error_t x509RegisterSignGenCallback(X509SignGenCallback callback)
{
#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Save callback function
   x509SignGenCallback = callback;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] signAlgoId Signature algorithm identifier
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const X509OctetString *tbsData, const X509SignAlgoId *signAlgoId,
   const void *privateKey, uint8_t *output, size_t *written)
{
   error_t error;
   X509SignatureAlgo signAlgo;
   const HashAlgo *hashAlgo;

#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Valid signature generation callback function?
   if(x509SignGenCallback != NULL)
   {
      //Invoke user-defined callback
      error = x509SignGenCallback(prngAlgo, prngContext, tbsData,
         signAlgoId, privateKey, output, written);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO ||
      error == ERROR_UNKOWN_KEY)
   {
      //Retrieve the signature algorithm that will be used to sign the
      //certificate
      error = x509GetSignHashAlgo(signAlgoId, &signAlgo, &hashAlgo);

      //Check status code
      if(!error)
      {
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA)
         {
            //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
            error = x509GenerateRsaSignature(tbsData, hashAlgo, privateKey,
               output, written);
         }
         else
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA-PSS signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA_PSS)
         {
            //Generate RSA signature (RSASSA-PSS signature scheme)
            error = x509GenerateRsaPssSignature(prngAlgo, prngContext, tbsData,
               hashAlgo, signAlgoId->rsaPssParams.saltLen, privateKey, output,
               written);
         }
         else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
         //DSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_DSA)
         {
            //Generate DSA signature
            error = x509GenerateDsaSignature(prngAlgo, prngContext, tbsData,
               hashAlgo, privateKey, output, written);
         }
         else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
         //ECDSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ECDSA)
         {
            //Generate ECDSA signature
            error = x509GenerateEcdsaSignature(prngAlgo, prngContext, tbsData,
               hashAlgo, privateKey, output, written);
         }
         else
#endif
#if (X509_SM2_SUPPORT == ENABLED && SM2_SUPPORT == ENABLED)
         //SM2 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_SM2)
         {
            //Generate SM2 signature
            error = x509GenerateSm2Signature(prngAlgo, prngContext, tbsData,
               hashAlgo, privateKey, output, written);
         }
         else
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
         //Ed25519 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED25519)
         {
            //Generate Ed25519 signature (PureEdDSA mode)
            error = x509GenerateEd25519Signature(tbsData, privateKey, output,
               written);
         }
         else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
         //Ed448 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED448)
         {
            //Generate Ed448 signature (PureEdDSA mode)
            error = x509GenerateEd448Signature(tbsData, privateKey, output,
               written);
         }
         else
#endif
         //Invalid signature algorithm?
         {
            //Report an error
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature generation
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] hashAlgo Underlying hash function
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateRsaSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const RsaPrivateKey *privateKey, uint8_t *output,
   size_t *written)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize status code
   error = NO_ERROR;

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting signature but will not generate a signature
   if(output != NULL)
   {
      //Digest the TBSCertificate structure using the specified hash algorithm
      error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

      //Check status code
      if(!error)
      {
         //Generate RSA signature
         error = rsassaPkcs1v15Sign(privateKey, hashAlgo, digest, output,
            written);
      }
   }
   else
   {
      //Length of the resulting RSA signature
      *written = mpiGetByteLength(&privateKey->n);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief RSA-PSS signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] hashAlgo Underlying hash function
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateRsaPssSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const X509OctetString *tbsData, const HashAlgo *hashAlgo, size_t saltLen,
   const RsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize status code
   error = NO_ERROR;

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting signature but will not generate a signature
   if(output != NULL)
   {
      //Digest the TBSCertificate structure using the specified hash algorithm
      error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

      //Check status code
      if(!error)
      {
         //Generate RSA-PSS signature
         error = rsassaPssSign(prngAlgo, prngContext, privateKey, hashAlgo,
            saltLen, digest, output, written);
      }
   }
   else
   {
      //Length of the resulting RSA-PSS signature
      *written = mpiGetByteLength(&privateKey->n);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] hashAlgo Underlying hash function
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateDsaSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const X509OctetString *tbsData, const HashAlgo *hashAlgo,
   const DsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;
   DsaSignature dsaSignature;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting signature but will not generate a signature
   if(output != NULL)
   {
      //Digest the TBSCertificate structure using the specified hash algorithm
      error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

      //Check status code
      if(!error)
      {
         //Generate DSA signature
         error = dsaGenerateSignature(prngAlgo, prngContext, privateKey, digest,
            hashAlgo->digestSize, &dsaSignature);
      }
   }
   else
   {
      //Generate a dummy (R, S) integer pair
      error = mpiSubInt(&dsaSignature.r, &privateKey->params.q, 1);

      //Check status code
      if(!error)
      {
         error = mpiSubInt(&dsaSignature.s, &privateKey->params.q, 1);
      }
   }

   //Check status code
   if(!error)
   {
      //Encode DSA signature using ASN.1
      error = dsaExportSignature(&dsaSignature, output, written);
   }

   //Release previously allocated resources
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] hashAlgo Underlying hash function
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateEcdsaSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const X509OctetString *tbsData, const HashAlgo *hashAlgo,
   const EcPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   error_t error;
   EcdsaSignature ecdsaSignature;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize status code
   error = NO_ERROR;

   //Initialize ECDSA signature
   ecdsaInitSignature(&ecdsaSignature);

   //Valid elliptic curve?
   if(privateKey->curve != NULL)
   {
      //If the output parameter is NULL, then the function calculates the
      //length of the resulting signature but will not generate a signature
      if(output != NULL)
      {
         //Digest the TBSCertificate structure using the specified hash
         //algorithm
         error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

         //Check status code
         if(!error)
         {
            //Generate ECDSA signature
            error = ecdsaGenerateSignature(prngAlgo, prngContext, privateKey,
               digest, hashAlgo->digestSize, &ecdsaSignature);
         }
      }
      else
      {
         //Save elliptic curve parameters
         ecdsaSignature.curve = privateKey->curve;

         //Generate a dummy (R, S) integer pair
         ecScalarSubInt(ecdsaSignature.r, privateKey->curve->q, 1,
            EC_MAX_ORDER_SIZE);

         ecScalarSubInt(ecdsaSignature.s, privateKey->curve->q, 1,
            EC_MAX_ORDER_SIZE);
      }

      //Check status code
      if(!error)
      {
         //Encode ECDSA signature using ASN.1
         error = ecdsaExportSignature(&ecdsaSignature, output, written,
            ECDSA_SIGNATURE_FORMAT_ASN1);
      }
   }
   else
   {
      //Invalid elliptic curve
      error = ERROR_INVALID_ELLIPTIC_CURVE;
   }

   //Release previously allocated resources
   ecdsaFreeSignature(&ecdsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief SM2 signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] hashAlgo Underlying hash function
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateSm2Signature(const PrngAlgo *prngAlgo, void *prngContext,
   const X509OctetString *tbsData, const HashAlgo *hashAlgo,
   const EcPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_SM2_SUPPORT == ENABLED && SM2_SUPPORT == ENABLED)
   error_t error;
   EcdsaSignature sm2Signature;

   //Initialize status code
   error = NO_ERROR;

   //Initialize SM2 signature
   ecdsaInitSignature(&sm2Signature);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting signature but will not generate a signature
   if(output != NULL)
   {
      //Generate SM2 signature
      error = sm2GenerateSignature(prngAlgo, prngContext, privateKey, hashAlgo,
         SM2_DEFAULT_ID, osStrlen(SM2_DEFAULT_ID), tbsData->value,
         tbsData->length, &sm2Signature);
   }
   else
   {
      //Generate a dummy (R, S) integer pair
      sm2Signature.curve = SM2_CURVE;
      ecScalarSubInt(sm2Signature.r, sm2Curve.q, 1, EC_MAX_ORDER_SIZE);
      ecScalarSubInt(sm2Signature.s, sm2Curve.q, 1, EC_MAX_ORDER_SIZE);
   }

   //Check status code
   if(!error)
   {
      //Encode SM2 signature using ASN.1
      error = ecdsaExportSignature(&sm2Signature, output, written,
         ECDSA_SIGNATURE_FORMAT_ASN1);
   }

   //Release previously allocated resources
   ecdsaFreeSignature(&sm2Signature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature generation
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateEd25519Signature(const X509OctetString *tbsData,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *q;

   //Initialize status code
   error = NO_ERROR;

   //Check elliptic curve parameters
   if(privateKey->curve == ED25519_CURVE)
   {
      //If the output parameter is NULL, then the function calculates the
      //length of the resulting signature but will not generate a signature
      if(output != NULL)
      {
         //The public key is optional
         q = (privateKey->q.curve != NULL) ? privateKey->q.q : NULL;

         //Generate Ed25519 signature (PureEdDSA mode)
         error = ed25519GenerateSignature(privateKey->d, q, tbsData->value,
            tbsData->length, NULL, 0, 0, output);
      }

      //Check status code
      if(!error)
      {
         //Length of the resulting EdDSA signature
         *written = ED25519_SIGNATURE_LEN;
      }
   }
   else
   {
      //The private key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature generation
 * @param[in] tbsData Pointer to the data to be signed
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateEd448Signature(const X509OctetString *tbsData,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *q;

   //Initialize status code
   error = NO_ERROR;

   //Check elliptic curve parameters
   if(privateKey->curve == ED448_CURVE)
   {
      //If the output parameter is NULL, then the function calculates the
      //length of the resulting signature but will not generate a signature
      if(output != NULL)
      {
         //The public key is optional
         q = (privateKey->q.curve != NULL) ? privateKey->q.q : NULL;

         //Generate Ed448 signature (PureEdDSA mode)
         error = ed448GenerateSignature(privateKey->d, q, tbsData->value,
            tbsData->length, NULL, 0, 0, output);
      }

      //Check status code
      if(!error)
      {
         //Length of the resulting EdDSA signature
         *written = ED448_SIGNATURE_LEN;
      }
   }
   else
   {
      //The private key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
