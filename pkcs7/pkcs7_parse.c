/**
 * @file pkcs7_parse.c
 * @brief PKCS #7 message parsing
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
#include "pkcs7/pkcs7_parse.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_sign_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS7_SUPPORT == ENABLED)


/**
 * @brief Parse contentInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] contentInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseContentInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7ContentInfo *contentInfo)
{
   error_t error;
   Asn1Tag tag;

   //Check parameters
   if(data == NULL || contentInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the contentInfo structure
   osMemset(contentInfo, 0, sizeof(Pkcs7ContentInfo));

   //The contentInfo structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse contentType field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the object identifier
   contentInfo->contentType.value = tag.value;
   contentInfo->contentType.length = tag.length;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //The content field is optional, and if the field is not present, its
   //intended value must be supplied by other means (refer to RFC 2315,
   //section 7)
   if(length > 0)
   {
      //Parse content field
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
      //Invalid tag?
      if(error)
         return error;

      //Save the inner content
      contentInfo->content.value = tag.value;
      contentInfo->content.length = tag.length;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse signed-data content
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] signedData Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseSignedData(const uint8_t *data, size_t length,
   Pkcs7SignedData *signedData)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Check parameters
   if(data == NULL || signedData == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SignedData structure
   osMemset(signedData, 0, sizeof(Pkcs7SignedData));

   //The SignedData structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse version field
   error = asn1ReadInt32(data, length, &tag, &signedData->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse digestAlgorithms field
   error = pkcs7ParseDigestAlgos(data, length, &n, &signedData->digestAlgos);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse contentInfo field
   error = pkcs7ParseContentInfo(data, length, &n, &signedData->contentInfo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse certificates field
   error = pkcs7ParseCertificates(data, length, &n, &signedData->certificates);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse crls field
   error = pkcs7ParseCrls(data, length, &n, &signedData->crls);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse signerInfos field
   error = pkcs7ParseSignerInfos(data, length, &n, &signedData->signerInfos);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse enveloped-data content
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] envelopedData Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseEnvelopedData(const uint8_t *data, size_t length,
   Pkcs7EnvelopedData *envelopedData)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Check parameters
   if(data == NULL || envelopedData == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the EnvelopedData structure
   osMemset(envelopedData, 0, sizeof(Pkcs7EnvelopedData));

   //The EnvelopedData structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse version field
   error = asn1ReadInt32(data, length, &tag, &envelopedData->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse recipientInfos field
   error = pkcs7ParseRecipientInfos(data, length, &n, &envelopedData->recipientInfos);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse encryptedContentInfo field
   error = pkcs7ParseEncryptedContentInfo(data, length, &n,
      &envelopedData->encryptedContentInfo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse digestAlgorithms structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] digestAlgos Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseDigestAlgos(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7DigestAlgos *digestAlgos)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509AlgoId identifier;

   //The digestAlgorithms structure is encapsulated within a set
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET);
   //Invalid tag?
   if(error)
      return error;

   //Save the total length of the set
   *totalLength = tag.totalLength;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //digestAlgorithms is a collection of message-digest algorithm identifiers.
   //There may be any number of elements in the collection, including zero
   //(refer to RFC 2315, section 9.1)
   for(i = 0; length > 0; i++)
   {
      //Parse current entry
      error = pkcs7ParseAlgoId(data, length, &n, &identifier);
      //Any error to report?
      if(error)
         return error;

      //Save digest algorithm identifier
      if(i < PKCS7_MAX_DIGEST_ALGO_IDENTIFIERS)
      {
         digestAlgos->identifiers[i] = identifier;
      }

      //Next field
      data += n;
      length -= n;
   }

   //Save the number of digest algorithm identifiers
   digestAlgos->numIdentifiers = MIN(i, PKCS7_MAX_DIGEST_ALGO_IDENTIFIERS);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse certificates
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certificates Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseCertificates(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7Certificates *certificates)
{
   error_t error;
   uint_t i;
   Asn1Tag tag;

   //Implicit tagging is used to encode the certificates field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
   //Invalid tag?
   if(error)
   {
      //The certificates field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the structure
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 structure
   certificates->raw.value = tag.value;
   certificates->raw.length = tag.length;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //The ExtendedCertificatesAndCertificates type gives a set of extended
   //certificates and X.509 certificates (refer to RFC 2315, section 6.6)
   for(i = 0; length > 0; i++)
   {
      //The ExtendedCertificateOrCertificate type gives either a PKCS #6
      //extended certificate or an X.509 certificate
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Save certificate
      if(i < PKCS7_MAX_CERTIFICATES)
      {
         certificates->certificates[i].value = data;
         certificates->certificates[i].length = tag.totalLength;
      }

      //Next field
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Save the number of certificates
   certificates->numCertificates = MIN(i, PKCS7_MAX_CERTIFICATES);

   //Exit immediately
   return NO_ERROR;
}


/**
 * @brief Parse CRLs
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] crls Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseCrls(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7Crls *crls)
{
   error_t error;
   uint_t i;
   Asn1Tag tag;

   //Implicit tagging is used to encode the crls field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 1);
   //Invalid tag?
   if(error)
   {
      //The crls field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the structure
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 structure
   crls->raw.value = tag.value;
   crls->raw.length = tag.length;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //The CertificateRevocationLists type gives a set of certificate-revocation
   //lists (refer to RFC 2315, section 6.1)
   for(i = 0; length > 0; i++)
   {
      //The CertificateRevocationList type contains information about
      //certificates whose validity an issuer has prematurely revoked
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Save CRL
      if(i < PKCS7_MAX_CRLS)
      {
         crls->crls[i].value = data;
         crls->crls[i].length = tag.totalLength;
      }

      //Next field
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Save the number of CRLs
   crls->numCrls = MIN(i, PKCS7_MAX_CRLS);

   //Exit immediately
   return NO_ERROR;
}


/**
 * @brief Parse signerInfos structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] signerInfos Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseSignerInfos(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7SignerInfos *signerInfos)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   Pkcs7SignerInfo signerInfo;

   //The signerInfos structure is encapsulated within a set
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET);
   //Invalid tag?
   if(error)
      return error;

   //Save the total length of the set
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 structure
   signerInfos->raw.value = tag.value;
   signerInfos->raw.length = tag.length;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //signerInfos is a collection of per-signer information. There may be any
   //number of elements in the collection, including zero (refer to RFC 2315,
   //section 9.1)
   for(i = 0; length > 0; i++)
   {
      //Per-signer information is represented in the type SignerInfo
      error = pkcs7ParseSignerInfo(data, length, &n, &signerInfo);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Save signer info
      if(i < PKCS7_MAX_SIGNER_INFOS)
      {
         signerInfos->signerInfos[i] = signerInfo;
      }

      //Next field
      data += n;
      length -= n;
   }

   //Save the number of signer infos
   signerInfos->numSignerInfos = MIN(i, PKCS7_MAX_SIGNER_INFOS);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse SignerInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] signerInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseSignerInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7SignerInfo *signerInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The SignerInfo structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse version field
   error = asn1ReadInt32(data, length, &tag, &signerInfo->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse issuerAndSerialNumber field
   error = pkcs7ParseIssuerAndSerialNumber(data, length, &n,
      &signerInfo->issuerAndSerialNumber);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse digestAlgorithm field
   error = pkcs7ParseAlgoId(data, length, &n, &signerInfo->digestAlgo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse authenticatedAttributes field
   error = pkcs7ParseAuthenticatedAttributes(data, length, &n,
      &signerInfo->authenticatedAttributes);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse digestEncryptionAlgorithm field
   error = pkcs7ParseDigestEncryptionAlgo(data, length, &n,
      &signerInfo->digestEncryptionAlgo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse encryptedDigest field
   error = pkcs7ParseEncryptedDigest(data, length, &n,
      &signerInfo->encryptedDigest);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //The unauthenticatedAttributes field is optional
   if(length > 0)
   {
      //Parse unauthenticatedAttributes field
      error = pkcs7ParseUnauthenticatedAttributes(data, length, &n,
         &signerInfo->unauthenticatedAttributes);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse IssuerAndSerialNumber structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] issuerAndSerialNumber Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseIssuerAndSerialNumber(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7IssuerAndSerialNumber *issuerAndSerialNumber)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The IssuerAndSerialNumber structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse name field
   error = x509ParseName(data, length, &n, &issuerAndSerialNumber->name);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse serialNumber field
   error = x509ParseSerialNumber(data, length, &n,
      &issuerAndSerialNumber->serialNumber);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse authenticatedAttributes structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] authenticatedAttributes Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseAuthenticatedAttributes(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7AuthenticatedAttributes *authenticatedAttributes)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   Pkcs7Attribute attribute;

   //Implicit tagging is used to encode the authenticatedAttributes field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
   //Invalid tag?
   if(error)
   {
      //The authenticatedAttributes field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the structure
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 structure
   authenticatedAttributes->raw.value = tag.value;
   authenticatedAttributes->raw.length = tag.length;

   //Point to the very first attribute
   data = tag.value;
   length = tag.length;

   //authenticatedAttributes is a set of attributes that are signed by the
   //signer (refer to RFC 2315, section 9.2)
   while(length > 0)
   {
      //Read current attribute
      error = pkcs7ParseAttribute(data, length, &n, &attribute);
      //Any error to report?
      if(error)
         return error;

      //PKCS #9 Content Type attribute found?
      if(OID_COMP(attribute.oid.value, attribute.oid.length,
         PKCS9_CONTENT_TYPE_OID) == 0)
      {
         //This attribute type specifies the content type of the ContentInfo
         //value being signed in PKCS #7 digitally signed data
         if(attribute.type == ASN1_TYPE_OBJECT_IDENTIFIER)
         {
            authenticatedAttributes->contentType.value = attribute.data.value;
            authenticatedAttributes->contentType.length = attribute.data.length;
         }
      }
      //PKCS #9 Message Digest attribute found?
      else if(OID_COMP(attribute.oid.value, attribute.oid.length,
         PKCS9_MESSAGE_DIGEST_OID) == 0)
      {
         //This attribute type specifies the message digest of the contents
         //octets of the DER-encoding of the content field of the ContentInfo
         //value being signed in PKCS #7 digitally signed data, where the
         //message digest is computed under the signer's message digest
         //algorithm
         if(attribute.type == ASN1_TYPE_OCTET_STRING)
         {
            authenticatedAttributes->messageDigest.value = attribute.data.value;
            authenticatedAttributes->messageDigest.length = attribute.data.length;
         }
      }
      //PKCS #9 Signing Time attribute found?
      else if(OID_COMP(attribute.oid.value, attribute.oid.length,
         PKCS9_SIGNING_TIME_OID) == 0)
      {
         //This attribute specifies the time at which the signer performed the
         //signing process
         if(attribute.type == ASN1_TYPE_UTC_TIME ||
            attribute.type == ASN1_TYPE_GENERALIZED_TIME)
         {
            //The date may be encoded as UTCTime or GeneralizedTime
            error = x509ParseTimeString(attribute.data.value,
               attribute.data.length, attribute.type,
               &authenticatedAttributes->signingTime);
         }
      }
      //Unknown attribute?
      else
      {
         //Discard current attribute
      }

      //Next attribute
      data += n;
      length -= n;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse digestEncryptionAlgorithm structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] digestEncryptionAlgo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseDigestEncryptionAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignAlgoId *digestEncryptionAlgo)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the digestEncryptionAlgorithm structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read the signature algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the signature algorithm identifier
   digestEncryptionAlgo->oid.value = tag.value;
   digestEncryptionAlgo->oid.length = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

#if (PKCS7_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSASSA-PSS algorithm identifier?
   if(!asn1CheckOid(&tag, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Read RSASSA-PSS parameters
      error = x509ParseRsaPssParameters(data, length,
         &digestEncryptionAlgo->rsaPssParams);
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //The parameters are optional
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse encryptedDigest structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] encryptedDigest Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseEncryptedDigest(const uint8_t *data, size_t length,
   size_t *totalLength, X509OctetString *encryptedDigest)
{
   error_t error;
   Asn1Tag tag;

   //The encryptedDigest structure is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Save encrypted digest
   encryptedDigest->value = tag.value;
   encryptedDigest->length = tag.length;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse unauthenticatedAttributes structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] unauthenticatedAttributes Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseUnauthenticatedAttributes(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7UnauthenticatedAttributes *unauthenticatedAttributes)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   Pkcs7Attribute attribute;

   //Implicit tagging is used to encode the unauthenticatedAttributes field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 1);
   //Invalid tag?
   if(error)
   {
      //The unauthenticatedAttributes field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the structure
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 structure
   unauthenticatedAttributes->raw.value = tag.value;
   unauthenticatedAttributes->raw.length = tag.length;

   //Point to the very first attribute
   data = tag.value;
   length = tag.length;

   //unauthenticatedAttributes is a set of attributes that are not signed by the
   //signer (refer to RFC 2315, section 9.2)
   while(length > 0)
   {
      //Read current attribute
      error = pkcs7ParseAttribute(data, length, &n, &attribute);
      //Any error to report?
      if(error)
         return error;

      //Next attribute
      data += n;
      length -= n;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse attribute
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] attribute Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseAttribute(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7Attribute *attribute)
{
   error_t error;
   Asn1Tag tag;

   //The attribute is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the attribute
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Parse attrType field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save attribute type
   attribute->oid.value = tag.value;
   attribute->oid.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Attribute values are encapsulated within a set
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET);
   //Invalid tag?
   if(error)
      return error;

   //Point to the first field of the set
   data = tag.value;
   length = tag.length;

   //Read AttributeValue field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save ASN.1 string type
   attribute->type = tag.objType;

   //Save attribute value
   attribute->data.value = tag.value;
   attribute->data.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Search a set of attributes for a given attribute type
 * @param[in] data Pointer to the set of attributes
 * @param[in] length Length of the set of attributes, in bytes
 * @param[out] oid Object identifier that specified the attribute type
 * @param[out] oidLen Length of the object identifier
 * @param[out] attribute Pointer to the matching attribute, if any
 * @return Error code
 **/

error_t pkcs7FindAttribute(const uint8_t *data, size_t length,
   const uint8_t *oid, size_t oidLen, Pkcs7Attribute *attribute)
{
   error_t error;
   size_t n;

   //Loop through the collection of attributes
   while(length > 0)
   {
      //Read current attribute
      error = pkcs7ParseAttribute(data, length, &n, attribute);
      //Any error to report?
      if(error)
         return error;

      //Check attribute type
      if(oidComp(attribute->oid.value, attribute->oid.length, oid, oidLen) == 0)
      {
         //We are done
         return NO_ERROR;
      }

      //Next attribute
      data += n;
      length -= n;
   }

   //The specified attribute was not found
   return ERROR_NOT_FOUND;
}


/**
 * @brief Parse recipientInfos structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] recipientInfos Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseRecipientInfos(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7RecipientInfos *recipientInfos)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   Pkcs7RecipientInfo recipientInfo;

   //The recipientInfos structure is encapsulated within a set
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET);
   //Invalid tag?
   if(error)
      return error;

   //Save the total length of the set
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 structure
   recipientInfos->raw.value = tag.value;
   recipientInfos->raw.length = tag.length;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //recipientInfos is a collection of per-recipient information. There must be
   //at least one element in the collection (refer to RFC 2315, section 10.1)
   if(length == 0)
      return ERROR_INVALID_SYNTAX;

   //Loop through the collection
   for(i = 0; length > 0; i++)
   {
      //Per-recipient information is represented in the type RecipientInfo
      error = pkcs7ParseRecipientInfo(data, length, &n, &recipientInfo);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Save signer info
      if(i < PKCS7_MAX_RECIPIENT_INFOS)
      {
         recipientInfos->recipientInfos[i] = recipientInfo;
      }

      //Next field
      data += n;
      length -= n;
   }

   //Save the number of recipient infos
   recipientInfos->numRecipientInfos = MIN(i, PKCS7_MAX_RECIPIENT_INFOS);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse RecipientInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] recipientInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseRecipientInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7RecipientInfo *recipientInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The RecipientInfo structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse version field
   error = asn1ReadInt32(data, length, &tag, &recipientInfo->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse issuerAndSerialNumber field
   error = pkcs7ParseIssuerAndSerialNumber(data, length, &n,
      &recipientInfo->issuerAndSerialNumber);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse keyEncryptionAlgorithm field
   error = pkcs7ParseAlgoId(data, length, &n,
      &recipientInfo->keyEncryptionAlgo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //Parse encryptedKey field
   error = pkcs7ParseEncryptedKey(data, length, &n,
      &recipientInfo->encryptedKey);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse encryptedKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] encryptedKey Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseEncryptedKey(const uint8_t *data, size_t length,
   size_t *totalLength, X509OctetString *encryptedKey)
{
   error_t error;
   Asn1Tag tag;

   //The encryptedKey structure is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Save encrypted key
   encryptedKey->value = tag.value;
   encryptedKey->length = tag.length;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse encryptedContentInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] encryptedContentInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseEncryptedContentInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7EncryptedContentInfo *encryptedContentInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The encryptedContentInfo structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse contentType field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the object identifier
   encryptedContentInfo->contentType.value = tag.value;
   encryptedContentInfo->contentType.length = tag.length;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse contentEncryptionAlgorithm field
   error = pkcs7ParseContentEncrAlgo(data, length, &n,
      &encryptedContentInfo->contentEncrAlgo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Next item
   data += n;
   length -= n;

   //The encryptedContent field is optional, and if the field is not present,
   //its intended value must be supplied by other means (refer to RFC 2315,
   //section 10.1)
   if(length > 0)
   {
      //Parse content field
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
      //Invalid tag?
      if(error)
         return error;

      //Save the inner content
      encryptedContentInfo->encryptedContent.value = tag.value;
      encryptedContentInfo->encryptedContent.length = tag.length;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse contentEncryptionAlgorithm structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] contentEncrAlgo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseContentEncrAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7ContentEncrAlgo *contentEncrAlgo)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the AlgorithmIdentifier structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Parse algorithm field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the algorithm identifier
   contentEncrAlgo->oid.value = tag.value;
   contentEncrAlgo->oid.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse CBCParameter field
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save initialization vector
   contentEncrAlgo->iv.value = tag.value;
   contentEncrAlgo->iv.length = tag.length;

   //Return status code
   return error;
}


/**
 * @brief Parse AlgorithmIdentifier structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] algoId Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs7ParseAlgoId(const uint8_t *data, size_t length,
   size_t *totalLength, X509AlgoId *algoId)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the AlgorithmIdentifier structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read the encryption algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the algorithm identifier
   algoId->oid.value = tag.value;
   algoId->oid.length = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

   //The contents of the optional parameters field will vary according to the
   //algorithm identified
   algoId->params.value = data;
   algoId->params.length = length;

   //Return status code
   return error;
}

#endif
