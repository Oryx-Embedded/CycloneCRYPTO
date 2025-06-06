/**
 * @file x509_sign_verify.c
 * @brief RSA/DSA/ECDSA/EdDSA signature verification
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
#include "pkix/x509_key_parse.h"
#include "pkix/x509_sign_verify.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)

//Signature generation/verification callback functions
#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   static X509SignVerifyCallback x509SignVerifyCallback = NULL;
#endif


/**
 * @brief Register signature verification callback function
 * @param[in] callback Signature verification callback function
 * @return Error code
 **/

error_t x509RegisterSignVerifyCallback(X509SignVerifyCallback callback)
{
#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Save callback function
   x509SignVerifyCallback = callback;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] signAlgoId Signature algorithm identifier
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifySignature(const X509OctetString *tbsData,
   const X509SignAlgoId *signAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
   error_t error;
   X509SignatureAlgo signAlgo;
   const HashAlgo *hashAlgo;

#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Valid signature verification callback function?
   if(x509SignVerifyCallback != NULL)
   {
      //Invoke user-defined callback
      error = x509SignVerifyCallback(tbsData, signAlgoId, publicKeyInfo,
         signature);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO)
   {
      //Retrieve the signature algorithm that was used to sign the certificate
      error = x509GetSignHashAlgo(signAlgoId, &signAlgo, &hashAlgo);

      //Check status code
      if(!error)
      {
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA)
         {
            //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
            error = x509VerifyRsaSignature(tbsData, hashAlgo, publicKeyInfo,
               signature);
         }
         else
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA-PSS signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA_PSS)
         {
            //Verify RSA signature (RSASSA-PSS signature scheme)
            error = x509VerifyRsaPssSignature(tbsData, hashAlgo,
               signAlgoId->rsaPssParams.saltLen, publicKeyInfo, signature);
         }
         else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
         //DSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_DSA)
         {
            //Verify DSA signature
            error = x509VerifyDsaSignature(tbsData, hashAlgo, publicKeyInfo,
               signature);
         }
         else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
         //ECDSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ECDSA)
         {
            //Verify ECDSA signature
            error = x509VerifyEcdsaSignature(tbsData, hashAlgo, publicKeyInfo,
               signature);
         }
         else
#endif
#if (X509_SM2_SUPPORT == ENABLED && SM2_SUPPORT == ENABLED)
         //SM2 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_SM2)
         {
            //Verify SM2 signature
            error = x509VerifySm2Signature(tbsData, hashAlgo, publicKeyInfo,
               signature);
         }
         else
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
         //Ed25519 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED25519)
         {
            //Verify Ed25519 signature (PureEdDSA mode)
            error = x509VerifyEd25519Signature(tbsData, publicKeyInfo,
               signature);
         }
         else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
         //Ed448 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED448)
         {
            //Verify Ed448 signature (PureEdDSA mode)
            error = x509VerifyEd448Signature(tbsData, publicKeyInfo,
               signature);
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
 * @brief RSA signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifyRsaSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   RsaPublicKey rsaPublicKey;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize RSA public key
   rsaInitPublicKey(&rsaPublicKey);

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

   //Check status code
   if(!error)
   {
      //Import the RSA public key
      error = x509ImportRsaPublicKey(&rsaPublicKey, publicKeyInfo);
   }

   //Check status code
   if(!error)
   {
      //Get the length of the modulus, in bits
      k = mpiGetBitLength(&rsaPublicKey.n);

      //Make sure the modulus is acceptable
      if(k < X509_MIN_RSA_MODULUS_SIZE || k > X509_MAX_RSA_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Check status code
   if(!error)
   {
      //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
      error = rsassaPkcs1v15Verify(&rsaPublicKey, hashAlgo, digest,
         signature->value, signature->length);
   }

   //Release previously allocated resources
   rsaFreePublicKey(&rsaPublicKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief RSA-PSS signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] hashAlgo Underlying hash function
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifyRsaPssSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, size_t saltLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   RsaPublicKey rsaPublicKey;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize RSA public key
   rsaInitPublicKey(&rsaPublicKey);

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

   //Check status code
   if(!error)
   {
      //Import the RSA public key
      error = x509ImportRsaPublicKey(&rsaPublicKey, publicKeyInfo);
   }

   //Check status code
   if(!error)
   {
      //Get the length of the modulus, in bits
      k = mpiGetBitLength(&rsaPublicKey.n);

      //Make sure the modulus is acceptable
      if(k < X509_MIN_RSA_MODULUS_SIZE || k > X509_MAX_RSA_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Check status code
   if(!error)
   {
      //Verify RSA signature (RSASSA-PSS signature scheme)
      error = rsassaPssVerify(&rsaPublicKey, hashAlgo, saltLen, digest,
         signature->value, signature->length);
   }

   //Release previously allocated resources
   rsaFreePublicKey(&rsaPublicKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifyDsaSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   DsaPublicKey dsaPublicKey;
   DsaSignature dsaSignature;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize DSA public key
   dsaInitPublicKey(&dsaPublicKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

   //Check status code
   if(!error)
   {
      //Import the DSA public key
      error = x509ImportDsaPublicKey(&dsaPublicKey, publicKeyInfo);
   }

   //Check status code
   if(!error)
   {
      //Get the length of the prime modulus, in bits
      k = mpiGetBitLength(&dsaPublicKey.params.p);

      //Make sure the prime modulus is acceptable
      if(k < X509_MIN_DSA_MODULUS_SIZE || k > X509_MAX_DSA_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Check status code
   if(!error)
   {
      //Read the ASN.1 encoded signature
      error = dsaImportSignature(&dsaSignature, signature->value,
         signature->length);
   }

   //Check status code
   if(!error)
   {
      //Verify DSA signature
      error = dsaVerifySignature(&dsaPublicKey, digest, hashAlgo->digestSize,
         &dsaSignature);
   }

   //Release previously allocated resources
   dsaFreePublicKey(&dsaPublicKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifyEcdsaSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   error_t error;
   const EcCurve *curve;
   EcPublicKey ecPublicKey;
   EcdsaSignature ecdsaSignature;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Initialize EC public key
   ecInitPublicKey(&ecPublicKey);
   //Initialize ECDSA signature
   ecdsaInitSignature(&ecdsaSignature);

   //Get the elliptic curve that matches the OID
   curve = x509GetCurve(publicKeyInfo->ecParams.namedCurve.value,
      publicKeyInfo->ecParams.namedCurve.length);

   //Make sure the specified elliptic curve is supported
   if(curve != NULL)
   {
      //Digest the TBSCertificate structure using the specified hash algorithm
      error = hashAlgo->compute(tbsData->value, tbsData->length, digest);

      //Check status code
      if(!error)
      {
         //Import the EC public key
         error = ecImportPublicKey(&ecPublicKey, curve,
            publicKeyInfo->ecPublicKey.q.value,
            publicKeyInfo->ecPublicKey.q.length, EC_PUBLIC_KEY_FORMAT_X963);
      }

      //Check status code
      if(!error)
      {
         //Read the ASN.1 encoded signature
         error = ecdsaImportSignature(&ecdsaSignature, curve, signature->value,
            signature->length, ECDSA_SIGNATURE_FORMAT_ASN1);
      }

      //Check status code
      if(!error)
      {
         //Verify ECDSA signature
         error = ecdsaVerifySignature(&ecPublicKey, digest,
            hashAlgo->digestSize, &ecdsaSignature);
      }
   }
   else
   {
      //Invalid elliptic curve
      error = ERROR_BAD_CERTIFICATE;
   }

   //Release previously allocated resources
   ecFreePublicKey(&ecPublicKey);
   ecdsaFreeSignature(&ecdsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief SM2 signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifySm2Signature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (X509_SM2_SUPPORT == ENABLED && SM2_SUPPORT == ENABLED)
   error_t error;
   EcPublicKey ecPublicKey;
   EcdsaSignature sm2Signature;

   //Initialize EC public key
   ecInitPublicKey(&ecPublicKey);
   //Initialize SM2 signature
   ecdsaInitSignature(&sm2Signature);

   //Import the EC public key
   error = ecImportPublicKey(&ecPublicKey, SM2_CURVE,
      publicKeyInfo->ecPublicKey.q.value,
      publicKeyInfo->ecPublicKey.q.length, EC_PUBLIC_KEY_FORMAT_X963);

   //Check status code
   if(!error)
   {
      //Read the ASN.1 encoded signature
      error = ecdsaImportSignature(&sm2Signature, SM2_CURVE, signature->value,
         signature->length, ECDSA_SIGNATURE_FORMAT_ASN1);
   }

   //Check status code
   if(!error)
   {
      //Verify SM2 signature
      error = sm2VerifySignature(&ecPublicKey, hashAlgo, SM2_DEFAULT_ID,
         osStrlen(SM2_DEFAULT_ID), tbsData->value, tbsData->length,
         &sm2Signature);
   }

   //Release previously allocated resources
   ecFreePublicKey(&ecPublicKey);
   ecdsaFreeSignature(&sm2Signature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifyEd25519Signature(const X509OctetString *tbsData,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   error_t error;

   //Check the length of the public key
   if(publicKeyInfo->ecPublicKey.q.length == ED25519_PUBLIC_KEY_LEN)
   {
      //Check the length of the EdDSA signature
      if(signature->length == ED25519_SIGNATURE_LEN)
      {
         //Verify signature (PureEdDSA mode)
         error = ed25519VerifySignature(publicKeyInfo->ecPublicKey.q.value,
            tbsData->value, tbsData->length, NULL, 0, 0, signature->value);
      }
      else
      {
         //The length of the EdDSA signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //The length of the Ed25519 public key is not valid
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature verification
 * @param[in] tbsData Data whose signature is to be verified
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t x509VerifyEd448Signature(const X509OctetString *tbsData,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   error_t error;

   //Check the length of the public key
   if(publicKeyInfo->ecPublicKey.q.length == ED448_PUBLIC_KEY_LEN)
   {
      //Check the length of the EdDSA signature
      if(signature->length == ED448_SIGNATURE_LEN)
      {
         //Verify signature (PureEdDSA mode)
         error = ed448VerifySignature(publicKeyInfo->ecPublicKey.q.value,
            tbsData->value, tbsData->length, NULL, 0, 0, signature->value);
      }
      else
      {
         //The length of the EdDSA signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //The length of the Ed448 public key is not valid
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
