/**
 * @file x509_signature_format.c
 * @brief RSA/DSA/ECDSA/EdDSA signature formatting
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
#include "pkix/x509_sign_format.h"
#include "pkix/x509_sign_generate.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Format SignatureAlgorithm structure
 * @param[in] signatureAlgo Pointer to the SignatureAlgorithm structure
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatSignatureAlgo(const X509SignAlgoId *signatureAlgo,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509SignatureAlgo signAlgo;
   const HashAlgo *hashAlgo;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Retrieve the signature algorithm that will be used to sign the certificate
   error = x509GetSignHashAlgo(signatureAlgo, &signAlgo, &hashAlgo);
   //Unsupported signature algorithm?
   if(error)
      return error;

   //The Algorithm field contains the OID for the algorithm used by the CA
   //to sign the certificate
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = signatureAlgo->oid.length;
   tag.value = signatureAlgo->oid.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_RSA)
   {
      //For RSA signature algorithm, the parameters component of that type
      //shall be the ASN.1 type NULL (refer to RFC 3279, section 2.2.1)
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_NULL;
      tag.length = 0;
      tag.value = NULL;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
   }
   else
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA-PSS signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_RSA_PSS)
   {
      //The parameters must be present when used in the algorithm identifier
      //associated with a signature value (refer to RFC 4055, section 3.1)
      error = x509FormatRsaPssParameters(&signatureAlgo->rsaPssParams, p, &n);
   }
   else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   //DSA signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_DSA)
   {
      //For DSA signature algorithm, the encoding shall omit the parameters
      //field (refer to RFC 3279, section 2.2.2)
      n = 0;
   }
   else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //ECDSA signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_ECDSA)
   {
      //For ECDSA signature algorithm, the encoding must omit the parameters
      //field (refer to RFC 3279, section 2.2.3)
      n = 0;
   }
   else
#endif
#if (X509_SM2_SUPPORT == ENABLED && SM2_SUPPORT == ENABLED)
   //SM2 signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_SM2)
   {
      //If the signature algorithm is SM2, no parameters are involved
      n = 0;
   }
   else
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   //Ed25519 signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_ED25519)
   {
      //The parameters must be absent (refer to RFC 8410, section 6)
      n = 0;
   }
   else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   //Ed448 signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_ED448)
   {
      //The parameters must be absent (refer to RFC 8410, section 6)
      n = 0;
   }
   else
#endif
   //Invalid signature algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The Algorithm and Parameters fields are encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = length + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SignatureValue field
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] signAlgoId Signature algorithm identifier
 * @param[in] publicKeyInfo Signer's public key information
 * @param[in] privateKey Signer's private key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatSignatureValue(const PrngAlgo *prngAlgo, void *prngContext,
   const X509OctetString *tbsCert, const X509SignAlgoId *signAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo, const void *privateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;

   //If the output parameter is NULL, then the function calculates the length
   //of the ASN.1 structure without copying any data
   if(p != NULL)
   {
      //The bit string shall contain an initial octet which encodes the number
      //of unused bits in the final subsequent octet
      p[0] = 0;

      //Advance data pointer
      p++;
   }

   //The ASN.1 DER-encoded tbsCertificate is used as the input to the signature
   //function
   error = x509GenerateSignature(prngAlgo, prngContext, tbsCert, signAlgoId,
      privateKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //The signature is encapsulated within a bit string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_BIT_STRING;
   tag.length = n + 1;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS parameters
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssParameters(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Format hashAlgorithm parameter
   error = x509FormatRsaPssHashAlgo(rsaPssParams, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format maskGenAlgorithm parameter
   error = x509FormatRsaPssMaskGenAlgo(rsaPssParams, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format saltLength parameter
   error = x509FormatRsaPssSaltLength(rsaPssParams, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The RSASSA-PSS parameters are encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS hash algorithm
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssHashAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   n = 0;

   //The default hash algorithm is SHA-1
   if(rsaPssParams->hashAlgo.value != NULL &&
      rsaPssParams->hashAlgo.length > 0)
   {
      //Write the hash algorithm identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = rsaPssParams->hashAlgo.length;
      tag.value = rsaPssParams->hashAlgo.value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //The hashAlgorithm parameter is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting sequence
      n = tag.totalLength;

      //Explicit tagging shall be used to encode each parameter
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 0;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting tag
      n = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS mask generation algorithm
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssMaskGenAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The default mask generation function is MGF1
   if(rsaPssParams->maskGenAlgo.value != NULL &&
      rsaPssParams->maskGenAlgo.length > 0)
   {
      //Write the mask generation algorithm identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = rsaPssParams->maskGenAlgo.length;
      tag.value = rsaPssParams->maskGenAlgo.value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Write the algorithm identifier of the one-way hash function employed
      //with the mask generation function
      error = x509FormatRsaPssMaskGenHashAlgo(rsaPssParams, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //The maskGenAlgorithm parameter is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting sequence
      n = tag.totalLength;

      //Explicit tagging shall be used to encode each parameter
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 1;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting tag
      length = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS mask generation hash algorithm
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssMaskGenHashAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   n = 0;

   //The default hash algorithm is SHA-1
   if(rsaPssParams->maskGenHashAlgo.value != NULL &&
      rsaPssParams->maskGenHashAlgo.length > 0)
   {
      //Write the algorithm identifier of the one-way hash function employed
      //with the mask generation function
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = rsaPssParams->maskGenHashAlgo.length;
      tag.value = rsaPssParams->maskGenHashAlgo.value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //The hash algorithm identifier is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting sequence
      n = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSASSA-PSS salt length
 * @param[in] rsaPssParams Pointer to the RSA-PSS parameters
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatRsaPssSaltLength(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   n = 0;

   //The default length of the salt is 20
   if(rsaPssParams->saltLen != 20)
   {
      //Write the length of the salt
      error = asn1WriteInt32((int32_t) rsaPssParams->saltLen, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Explicit tagging shall be used to encode the saltLength parameter
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 2;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting tag
      n = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}

#endif
