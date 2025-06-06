/**
 * @file pkcs7_format.c
 * @brief PKCS #7 message formatting
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
#include "pkcs7/pkcs7_format.h"
#include "pkcs7/pkcs7_encrypt.h"
#include "pkcs7/pkcs7_sign_generate.h"
#include "pkix/x509_cert_format.h"
#include "pkix/x509_sign_format.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS7_SUPPORT == ENABLED)


/**
 * @brief Format contentInfo structure
 * @param[in] contentInfo Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatContentInfo(const Pkcs7ContentInfo *contentInfo,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   const uint8_t *content;
   size_t contentLen;
   Asn1Tag tag;

   //Point to the content
   content = contentInfo->content.value;
   contentLen = contentInfo->content.length;

   //Two-pass processing
   for(i = 0; i < 2; i++)
   {
      //Point to the buffer where to write the ASN.1 structure
      p = (i == 0) ? NULL : output;
      //Length of the ASN.1 structure
      length = 0;

      //Format contentType field
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = contentInfo->contentType.length;
      tag.value = contentInfo->contentType.value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //The content field is optional, and if the field is not present, its
      //intended value must be supplied by other means (refer to RFC 2315,
      //section 7)
      if(contentInfo->content.length > 0)
      {
         //Copy the content
         if(p != NULL)
         {
            osMemmove(p, content, contentLen);
         }

         //Its type is defined along with the object identifier for contentType
         if(OID_COMP(contentInfo->contentType.value,
            contentInfo->contentType.length, PKCS7_DATA_OID) == 0)
         {
            //The data content type is just an octet string (refer to RFC 2315,
            //section 8)
            tag.constructed = FALSE;
            tag.objClass = ASN1_CLASS_UNIVERSAL;
            tag.objType = ASN1_TYPE_OCTET_STRING;
            tag.length = contentLen;

            //Write the corresponding ASN.1 tag
            error = asn1InsertHeader(&tag, p, &n);
            //Any error to report?
            if(error)
               return error;
         }
         else
         {
            //The content field can contain any content type
            n = 0;
         }

         //Explicit tagging shall be used to encode the content field
         tag.constructed = TRUE;
         tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
         tag.objType = 0;
         tag.length = contentLen + n;

         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, tag.totalLength);
         length += tag.totalLength;
      }

      //The contentInfo structure is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;

      //First pass?
      if(i == 0)
      {
         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, NULL, &n);
         //Any error to report?
         if(error)
            return error;

         //The first pass calculates the length of the ASN.1 structure
         n = tag.totalLength;

         //If the output parameter is NULL, then the function calculates the
         //length of the ASN.1 structure without copying any data
         if(output != NULL)
         {
            //Copy the message
            osMemmove(output + n - contentLen, content, contentLen);
            content = output + n - contentLen;
         }
      }
      else
      {
         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, output, &n);
         //Any error to report?
         if(error)
            return error;

         //The second pass generates the ASN.1 structure
         *written = tag.totalLength;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format signed-data content
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] signedData Pointer to the structure to format
 * @param[in] signerPrivateKey Pointer to the signer's private key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatSignedData(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7SignedData *signedData, const void *signerPrivateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   Pkcs7ContentInfo contentInfo;

   //contentInfo is the content that is signed
   contentInfo = signedData->contentInfo;

   //Two-pass processing
   for(i = 0; i < 2; i++)
   {
      //Point to the buffer where to write the ASN.1 structure
      p = (i == 0) ? NULL : output;
      //Length of the ASN.1 structure
      length = 0;

      //Format version field
      error = asn1WriteInt32(signedData->version, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format digestAlgorithms field
      error = pkcs7FormatDigestAlgos(&signedData->digestAlgos, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format contentInfo field
      error = pkcs7FormatContentInfo(&contentInfo, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format certificates field
      error = pkcs7FormatCertificates(&signedData->certificates, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format crls field
      error = pkcs7FormatCrls(&signedData->crls, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format signerInfos field
      error = pkcs7FormatSignerInfos(prngAlgo, prngContext,
         &signedData->signerInfos, signerPrivateKey, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //The SignedData structure is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;

      //First pass?
      if(i == 0)
      {
         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, NULL, &n);
         //Any error to report?
         if(error)
            return error;

         //The first pass calculates the length of the ASN.1 structure
         n = tag.totalLength;

         //If the output parameter is NULL, then the function calculates the
         //length of the ASN.1 structure without copying any data
         if(output != NULL)
         {
            //Copy the message
            osMemmove(output + n - contentInfo.content.length,
               contentInfo.content.value, contentInfo.content.length);

            contentInfo.content.value = output + n - contentInfo.content.length;
         }
      }
      else
      {
         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, output, &n);
         //Any error to report?
         if(error)
            return error;

         //The second pass generates the ASN.1 structure
         *written = tag.totalLength;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format enveloped-data content
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[in] envelopedData Pointer to the structure to format
 * @param[in] plaintext Pointer to the message to be encrypted
 * @param[in] plaintextLen Length of the message, in bytes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatEnvelopedData(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertInfo *recipientCertInfo, const Pkcs7EnvelopedData *envelopedData,
   const uint8_t *plaintext, size_t plaintextLen, uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   uint8_t key[32];
   size_t keyLen;
   Asn1Tag tag;

   //Obtain the key length in octets
   keyLen = pkcs7GetKeyLength(envelopedData->encryptedContentInfo.contentEncrAlgo.oid.value,
      envelopedData->encryptedContentInfo.contentEncrAlgo.oid.length);
   //Invalid key length?
   if(keyLen == 0)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //Generate a random encryption key
   error = prngAlgo->generate(prngContext, key, keyLen);
   //Any error to report?
   if(error)
      return error;

   //Two-pass processing
   for(i = 0; i < 2; i++)
   {
      //Point to the buffer where to write the ASN.1 structure
      p = (i == 0) ? NULL : output;
      //Length of the ASN.1 structure
      length = 0;

      //Format version field
      error = asn1WriteInt32(envelopedData->version, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format recipientInfos field
      error = pkcs7FormatRecipientInfos(prngAlgo, prngContext,
         &envelopedData->recipientInfos, recipientCertInfo, key, keyLen, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format encryptedContentInfo field
      error = pkcs7FormatEncryptedContentInfo(&envelopedData->encryptedContentInfo,
         key, keyLen, plaintext, plaintextLen, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //The EnvelopedData structure is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;

      //First pass?
      if(i == 0)
      {
         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, NULL, &n);
         //Any error to report?
         if(error)
            return error;

         //The first pass calculates the length of the ASN.1 structure
         n = tag.totalLength;

         //Copy the message to be encrypted
         if(output != NULL)
         {
            osMemmove(output + n - plaintextLen, plaintext, plaintextLen);
            plaintext = output + n - plaintextLen;
         }
      }
      else
      {
         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, output, &n);
         //Any error to report?
         if(error)
            return error;

         //The second pass generates the ASN.1 structure
         *written = tag.totalLength;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format digestAlgos structure
 * @param[in] digestAlgos Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatDigestAlgos(const Pkcs7DigestAlgos *digestAlgos,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //digestAlgorithms is a collection of message-digest algorithm identifiers.
   //There may be any number of elements in the collection, including zero
   //(refer to RFC 2315, section 9.1)
   for(i = 0; i < digestAlgos->numIdentifiers; i++)
   {
      //Format DigestAlgorithmIdentifier structure
      error = pkcs7FormatAlgoId(&digestAlgos->identifiers[i], p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;
   }

   //The digestAlgorithms structure is encapsulated within a set
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SET;
   tag.length = n;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the ASN.1 structure
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format certificates
 * @param[in] certificates Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatCertificates(const Pkcs7Certificates *certificates,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Raw ASN.1 sequence?
   if(certificates->raw.value != NULL && certificates->raw.length > 0)
   {
      //Copy raw ASN.1 sequence
      if(output != NULL)
      {
         osMemcpy(p, certificates->raw.value, certificates->raw.length);
      }

      //Advance data pointer
      ASN1_INC_POINTER(p, certificates->raw.length);
      length += certificates->raw.length;
   }
   else
   {
      //The ExtendedCertificatesAndCertificates type gives a set of extended
      //certificates and X.509 certificates (refer to RFC 2315, section 6.6)
      for(i = 0; i < certificates->numCertificates; i++)
      {
         //The ExtendedCertificateOrCertificate type gives either a PKCS #6
         //extended certificate or an X.509 certificate
         if(output != NULL)
         {
            osMemcpy(p, certificates->certificates[i].value,
               certificates->certificates[i].length);
         }

         //Advance data pointer
         ASN1_INC_POINTER(p, certificates->certificates[i].length);
         length += certificates->certificates[i].length;
      }
   }

   //The certificates field is optional
   if(length > 0)
   {
      //Implicit tagging is used to encode the crls field
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 0;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Total length of the ASN.1 structure
      *written = tag.totalLength;
   }
   else
   {
      //The certificates field is not present
      *written = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format CRLs
 * @param[in] crls Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatCrls(const Pkcs7Crls *crls, uint8_t *output,
   size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Raw ASN.1 sequence?
   if(crls->raw.value != NULL && crls->raw.length > 0)
   {
      //Copy raw ASN.1 sequence
      if(output != NULL)
      {
         osMemcpy(p, crls->raw.value, crls->raw.length);
      }

      //Advance data pointer
      ASN1_INC_POINTER(p, crls->raw.length);
      length += crls->raw.length;
   }
   else
   {
      //The CertificateRevocationLists type gives a set of certificate-
      //revocation lists (refer to RFC 2315, section 6.1)
      for(i = 0; i < crls->numCrls; i++)
      {
         //The CertificateRevocationList type contains information about
         //certificates whose validity an issuer has prematurely revoked
         if(output != NULL)
         {
            osMemcpy(p, crls->crls[i].value, crls->crls[i].length);
         }

         //Advance data pointer
         ASN1_INC_POINTER(p, crls->crls[i].length);
         length += crls->crls[i].length;
      }
   }

   //The crls field is optional
   if(length > 0)
   {
      //Implicit tagging is used to encode the crls field
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 1;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Total length of the ASN.1 structure
      *written = tag.totalLength;
   }
   else
   {
      //The crls field is not present
      *written = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SignerInfos structure
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] signerInfos Pointer to the structure to format
 * @param[in] signerPrivateKey Pointer to the signer's private key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatSignerInfos(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7SignerInfos *signerInfos, const void *signerPrivateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //signerInfos is a collection of per-signer information. There may be any
   //number of elements in the collection, including zero (refer to RFC 2315,
   //section 9.1)
   for(i = 0; i < signerInfos->numSignerInfos; i++)
   {
      //Format SignerInfo structure
      error = pkcs7FormatSignerInfo(prngAlgo, prngContext,
         &signerInfos->signerInfos[i], signerPrivateKey, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;
   }

   //The signerInfos structure is encapsulated within a set
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SET;
   tag.length = n;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the ASN.1 structure
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SignerInfo structure
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] signerInfo Pointer to the structure to format
 * @param[in] signerPrivateKey Pointer to the signer's private key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatSignerInfo(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7SignerInfo *signerInfo, const void *signerPrivateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Format version field
   error = asn1WriteInt32(signerInfo->version, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format issuerAndSerialNumber field
   error = pkcs7FormatIssuerAndSerialNumber(&signerInfo->issuerAndSerialNumber,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format digestAlgorithm field
   error = pkcs7FormatAlgoId(&signerInfo->digestAlgo, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format authenticatedAttributes field
   error = pkcs7FormatAuthenticatedAttributes(&signerInfo->authenticatedAttributes,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //If the output parameter is NULL, then the function calculates the length
   //of the ASN.1 structure without copying any data
   if(p != NULL)
   {
      //The IMPLICIT [0] tag in the authenticatedAttributes field is not part
      //of the Attributes value (refer to RFC 2315, section 9.3)
      error = asn1ReadTag(p, n, &tag);
      //Any error to report?
      if(error)
         return error;

      //Digest the DER encoding of the authenticatedAttributes field
      error = pkcs7DigestAuthenticatedAttributes(signerInfo, tag.value,
         tag.length, digest);
      //Any error to report?
      if(error)
         return error;
   }

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format digestEncryptionAlgorithm field
   error = pkcs7FormatDigestEncryptionAlgo(&signerInfo->digestEncryptionAlgo,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format encryptedDigest field
   error = pkcs7FormatEncryptedDigest(prngAlgo, prngContext, digest,
      signerInfo, signerPrivateKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format unauthenticatedAttributes field
   error = pkcs7FormatUnauthenticatedAttributes(&signerInfo->unauthenticatedAttributes,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The SignerInfo structure is encapsulated within a sequence
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
 * @brief Format IssuerAndSerialNumber structure
 * @param[in] issuerAndSerialNumber Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatIssuerAndSerialNumber(const Pkcs7IssuerAndSerialNumber *issuerAndSerialNumber,
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

   //Format issuer field
   error = x509FormatName(&issuerAndSerialNumber->name, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format serialNumber field
   error = x509FormatSerialNumber(NULL, NULL,
      &issuerAndSerialNumber->serialNumber, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The IssuerAndSerialNumber structure is encapsulated within a sequence
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
 * @brief Format authenticatedAttributes structure
 * @param[in] authenticatedAttributes Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatAuthenticatedAttributes(const Pkcs7AuthenticatedAttributes *authenticatedAttributes,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   Asn1Tag tag;
   Pkcs7Attribute attribute;

   //Length of the ASN.1 structure
   length = 0;

   //Format PKCS #9 Content Type attribute
   if(authenticatedAttributes->contentType.length > 0)
   {
      //Set attribute type and value
      attribute.oid.value = PKCS9_CONTENT_TYPE_OID;
      attribute.oid.length = sizeof(PKCS9_CONTENT_TYPE_OID);
      attribute.type = ASN1_TYPE_OBJECT_IDENTIFIER;
      attribute.data.value = authenticatedAttributes->contentType.value;
      attribute.data.length = authenticatedAttributes->contentType.length;

      //Encode the attribute to ASN.1 format
      error = pkcs7AddAttribute(&attribute, output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Format PKCS #9 Message Digest attribute
   if(authenticatedAttributes->messageDigest.length > 0)
   {
      //Set attribute type and value
      attribute.oid.value = PKCS9_MESSAGE_DIGEST_OID;
      attribute.oid.length = sizeof(PKCS9_MESSAGE_DIGEST_OID);
      attribute.type = ASN1_TYPE_OCTET_STRING;
      attribute.data.value = authenticatedAttributes->messageDigest.value;
      attribute.data.length = authenticatedAttributes->messageDigest.length;

      //Encode the attribute to ASN.1 format
      error = pkcs7AddAttribute(&attribute, output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Format PKCS #9 Signing Time attribute
   if(authenticatedAttributes->signingTime.year > 0)
   {
      char_t buffer[24];

      //UTCTime is limited to the period from 1950 to 2049
      if(authenticatedAttributes->signingTime.year >= 1950 &&
         authenticatedAttributes->signingTime.year <= 2049)
      {
         //Use UTCTime format
         attribute.type = ASN1_TYPE_UTC_TIME;
      }
      else
      {
         //Use GeneralizedTime format
         attribute.type = ASN1_TYPE_GENERALIZED_TIME;
      }

      //Format UTCTime or GeneralizedTime string
      error = x509FormatTimeString(&authenticatedAttributes->signingTime,
         attribute.type, buffer);
      //Any error to report?
      if(error)
         return error;

      //Set attribute type and value
      attribute.oid.value = PKCS9_SIGNING_TIME_OID;
      attribute.oid.length = sizeof(PKCS9_SIGNING_TIME_OID);
      attribute.data.value = (uint8_t *) buffer;
      attribute.data.length = osStrlen(buffer);

      //Encode the attribute to ASN.1 format
      error = pkcs7AddAttribute(&attribute, output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Add custom attributes, if any
   for(i = 0; i < authenticatedAttributes->numCustomAttributes; i++)
   {
      //Encode the attribute to ASN.1 format
      error = pkcs7AddAttribute(&authenticatedAttributes->customAttributes[i],
         output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Any attributes written?
   if(length > 0)
   {
      //Implicit tagging shall be used to encode the authenticatedAttributes
      //structure
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 0;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Total length of the ASN.1 structure
      *written = tag.totalLength;
   }
   else
   {
      //The authenticatedAttributes field is optional
      *written = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format digestEncryptionAlgorithm structure
 * @param[in] digestEncryptionAlgo Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatDigestEncryptionAlgo(const X509SignAlgoId *digestEncryptionAlgo,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Get the signature algorithm identifier
   oid = digestEncryptionAlgo->oid.value;
   oidLen = digestEncryptionAlgo->oid.length;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //digestEncryptionAlgorithm identifies the digest-encryption algorithm under
   //which the message digest and associated information are encrypted with the
   //signer's private key (refer to RFC 2315, section 9.2)
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = digestEncryptionAlgo->oid.length;
   tag.value = digestEncryptionAlgo->oid.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

#if (PKCS7_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, MD5_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA1_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA224_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA256_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA384_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA512_WITH_RSA_ENCRYPTION_OID) == 0)
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
#if (PKCS7_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA-PSS signature algorithm?
   if(OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //The parameters must be present when used in the algorithm identifier
      //associated with a signature value (refer to RFC 4055, section 3.1)
      error = x509FormatRsaPssParameters(&digestEncryptionAlgo->rsaPssParams,
         p, &n);
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
 * @brief Format encryptedDigest structure
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] digest Message digest
 * @param[in] signerInfo Pointer to the signer information
 * @param[in] signerPrivateKey Pointer to the signer's private key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatEncryptedDigest(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *digest, const Pkcs7SignerInfo *signerInfo,
   const void *signerPrivateKey, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //encryptedDigest is the result of digital signature generation, using the
   //message digest and the signer's private key
   error = pkcs7GenerateSignature(prngAlgo, prngContext, digest, signerInfo,
      signerPrivateKey, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The signature value generated by the signer must be encoded as an octet
   //string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = n;

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
 * @brief Format unauthenticatedAttributes structure
 * @param[in] unauthenticatedAttributes Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatUnauthenticatedAttributes(const Pkcs7UnauthenticatedAttributes *unauthenticatedAttributes,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   Asn1Tag tag;

   //Length of the ASN.1 structure
   length = 0;

   //Add custom attributes, if any
   for(i = 0; i < unauthenticatedAttributes->numCustomAttributes; i++)
   {
      //Encode the attribute to ASN.1 format
      error = pkcs7AddAttribute(&unauthenticatedAttributes->customAttributes[i],
         output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Any attributes written?
   if(length > 0)
   {
      //Implicit tagging shall be used to encode the unauthenticatedAttributes
      //structure
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 1;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Total length of the ASN.1 structure
      *written = tag.totalLength;
   }
   else
   {
      //The unauthenticatedAttributes field is optional
      *written = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format attribute
 * @param[in] attribute Pointer to the attribute to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatAttribute(const Pkcs7Attribute *attribute, uint8_t *output,
   size_t *written)
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

   //Format attrType field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = attribute->oid.length;
   tag.value = attribute->oid.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format AttributeValue field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = attribute->type;
   tag.length = attribute->data.length;
   tag.value = attribute->data.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Attribute values are encapsulated within a set
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SET;
   tag.length = n;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the resulting tag
   n = tag.totalLength;

   //The attribute is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length + n;

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
 * @brief Add attribute
 * @param[in] attribute Pointer to the attribute to add
 * @param[in] attributes Pointer to the list of attributes
 * @param[in,out] length Actual length of the list of attributes
 * @return Error code
 **/

error_t pkcs7AddAttribute(const Pkcs7Attribute *attribute, uint8_t *attributes,
   size_t *length)
{
   error_t error;
   size_t i;
   size_t n;
   uint8_t *p;
   Asn1Tag tag;

   //If the output parameter is NULL, then the function calculates the
   //length of the ASN.1 structure without copying any data
   if(attributes != NULL)
   {
      //Point to the buffer where to format the new attribute
      p = attributes + *length;

      //Encode the attribute to ASN.1 format
      error = pkcs7FormatAttribute(attribute, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Loop through the collection of attributes
      for(i = 0; i < *length; i += tag.totalLength)
      {
         //Each attribute is encapsulated within a sequence
         error = asn1ReadSequence(attributes + i, *length - i, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            return error;

         //Sort attributes in ascending order
         if(pkcs7CompAttributes(p, n, attributes + i, tag.totalLength) < 0)
         {
            //Make room for the new attribute
            osMemmove(attributes + i + n, attributes + i, *length - i);

            //Encode the attribute to ASN.1 format
            error = pkcs7FormatAttribute(attribute, attributes + i, &n);
            //Any error to report?
            if(error)
               return error;

            //We are done
            break;
         }
      }
   }
   else
   {
      //Calculate the length of the ASN.1 structure
      error = pkcs7FormatAttribute(attribute, NULL, &n);
      //Any error to report?
      if(error)
         return error;
   }

   //Update the length of the list of attributes
   *length += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format recipientInfos structure
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] recipientInfos Pointer to the structure to format
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[in] key Pointer to the encryption key
 * @param[in] keyLen Length of the encryption key, in bytes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatRecipientInfos(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7RecipientInfos *recipientInfos, const X509CertInfo *recipientCertInfo,
   const uint8_t *key, size_t keyLen, uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //recipientInfos is a collection of per-recipient information. There must be
   //at least one element in the collection (refer to RFC 2315, section 10.1)
   for(i = 0; i < recipientInfos->numRecipientInfos; i++)
   {
      //Format RecipientInfo structure
      error = pkcs7FormatRecipientInfo(prngAlgo, prngContext,
         &recipientInfos->recipientInfos[i], recipientCertInfo, key, keyLen,
         p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;
   }

   //The recipientInfos structure is encapsulated within a set
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SET;
   tag.length = n;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the ASN.1 structure
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RecipientInfo structure
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] recipientInfo Pointer to the structure to format
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[in] key Pointer to the encryption key
 * @param[in] keyLen Length of the encryption key, in bytes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatRecipientInfo(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7RecipientInfo *recipientInfo, const X509CertInfo *recipientCertInfo,
   const uint8_t *key, size_t keyLen, uint8_t *output, size_t *written)
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

   //Format version field
   error = asn1WriteInt32(recipientInfo->version, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format issuerAndSerialNumber field
   error = pkcs7FormatIssuerAndSerialNumber(&recipientInfo->issuerAndSerialNumber,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format keyEncryptionAlgorithm field
   error = pkcs7FormatAlgoId(&recipientInfo->keyEncryptionAlgo, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format encryptedKey field
   error = pkcs7FormatEncryptedKey(prngAlgo, prngContext,
      recipientCertInfo, key, keyLen, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The RecipientInfo structure is encapsulated within a sequence
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
 * @brief Format encryptedKey structure
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[in] key Pointer to the encryption key
 * @param[in] keyLen Length of the encryption key, in bytes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatEncryptedKey(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertInfo *recipientCertInfo, const uint8_t *key, size_t keyLen,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //encryptedKey is the result of encrypting the content-encryption key
   //with the recipient's public key (refer to RFC 2315, section 10.2)
   error = pkcs7EncryptKey(prngAlgo, prngContext, recipientCertInfo, key,
      keyLen, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The encrypted key is encapsulated within an octet string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = n;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the ASN.1 structure
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format encryptedContentInfo structure
 * @param[in] encryptedContentInfo Pointer to the structure to format
 * @param[in] key Pointer to the encryption key
 * @param[in] keyLen Length of the encryption key, in bytes
 * @param[in] plaintext Pointer to the message to be encrypted
 * @param[in] plaintextLen Length of the message, in bytes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatEncryptedContentInfo(const Pkcs7EncryptedContentInfo *encryptedContentInfo,
   const uint8_t *key, size_t keyLen, const uint8_t *plaintext, size_t plaintextLen,
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

   //Format contentType field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = encryptedContentInfo->contentType.length;
   tag.value = encryptedContentInfo->contentType.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format contentEncryptionAlgorithm field
   error = pkcs7FormatContentEncrAlgo(&encryptedContentInfo->contentEncrAlgo,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The encryptedContent field is optional, and if the field is not present,
   //its intended value must be supplied by other means (refer to RFC 2315,
   //section 10.1)
   if(plaintextLen > 0)
   {
      //The encryptedContent field is the result of encrypting the content
      error = pkcs7EncryptData(encryptedContentInfo, key, keyLen, plaintext,
         plaintextLen, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Explicit tagging shall be used to encode the encryptedContent field
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 0;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, tag.totalLength);
      length += tag.totalLength;
   }

   //The encryptedContentInfo structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the ASN.1 structure
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format contentEncryptionAlgorithm structure
 * @param[in] contentEncrAlgo Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatContentEncrAlgo(const Pkcs7ContentEncrAlgo *contentEncrAlgo,
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

   //Format algorithm field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = contentEncrAlgo->oid.length;
   tag.value = contentEncrAlgo->oid.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format CBCParameter field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = contentEncrAlgo->iv.length;
   tag.value = contentEncrAlgo->iv.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The AlgorithmIdentifier structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the ASN.1 structure
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format AlgorithmIdentifier structure
 * @param[in] algoId Pointer to the structure to format
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7FormatAlgoId(const X509AlgoId *algoId, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The algorithm identifier is used to identify a cryptographic algorithm
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = algoId->oid.length;
   tag.value = algoId->oid.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The AlgorithmIdentifier structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = n;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the ASN.1 structure
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}

#endif
