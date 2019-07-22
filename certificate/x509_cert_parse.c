/**
 * @file x509_cert_parse.c
 * @brief X.509 certificate parsing
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2019 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.9.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "certificate/x509_cert_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "hash/md5.h"
#include "hash/sha1.h"
#include "hash/sha224.h"
#include "hash/sha256.h"
#include "hash/sha384.h"
#include "hash/sha512.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Parse a X.509 certificate
 * @param[in] data Pointer to the X.509 certificate to parse
 * @param[in] length Length of the X.509 certificate
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCertificate(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   size_t totalLength;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Parsing X.509 certificate...\r\n");

   //Clear the certificate information structure
   cryptoMemset(certInfo, 0, sizeof(X509CertificateInfo));

   //Where pathLenConstraint does not appear, no limit is imposed
   certInfo->extensions.basicConstraints.pathLenConstraint = -1;

   //Read the contents of the certificate
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse TBSCertificate structure
   error = x509ParseTbsCertificate(data, length, &totalLength, certInfo);
   //Any error to report?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //Point to the next field
   data += totalLength;
   length -= totalLength;

   //Parse SignatureAlgorithm structure
   error = x509ParseSignatureAlgo(data, length, &totalLength,
      &certInfo->signatureAlgo);
   //Any error to report?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //Point to the next field
   data += totalLength;
   length -= totalLength;

   //Parse SignatureValue structure
   error = x509ParseSignatureValue(data, length, &totalLength,
      &certInfo->signatureValue);
   //Any error to report?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //Certificate successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse TBSCertificate structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseTbsCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing TBSCertificate...\r\n");

   //Read the contents of the TBSCertificate structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The ASN.1 DER encoded TBSCertificate is used as the input to the
   //signature function
   certInfo->tbsCertificate = data;
   certInfo->tbsCertificateLen = tag.totalLength;

   //Point to the very first field of the TBSCertificate
   data = tag.value;
   length = tag.length;

   //Parse Version field
   error = x509ParseVersion(data, length, &n, &certInfo->version);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SerialNumber field
   error = x509ParseSerialNumber(data, length, &n, &certInfo->serialNumber);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Signature field
   error = x509ParseSignature(data, length, &n, &certInfo->signatureAlgo);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Issuer field
   error = x509ParseName(data, length, &n, &certInfo->issuer);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Validity field
   error = x509ParseValidity(data, length, &n, &certInfo->validity);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Subject field
   error = x509ParseName(data, length, &n, &certInfo->subject);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SubjectPublicKeyInfo field
   error = x509ParseSubjectPublicKeyInfo(data, length, &n,
      &certInfo->subjectPublicKeyInfo);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse IssuerUniqueID field
   error = x509ParseIssuerUniqueId(data, length, &n);
   //Any parsing error?
   if(error)
      return error;

   //The IssuerUniqueID field is optional
   if(n > 0)
   {
      //This field must only appear if the version is 2 or 3
      if(certInfo->version < X509_VERSION_2)
         return ERROR_INVALID_VERSION;
   }

   //Point to the next field
   data += n;
   length -= n;

   //Parse SubjectUniqueID field
   error = x509ParseSubjectUniqueId(data, length, &n);
   //Any parsing error?
   if(error)
      return error;

   //The SubjectUniqueID field is optional
   if(n > 0)
   {
      //This field must only appear if the version is 2 or 3
      if(certInfo->version < X509_VERSION_2)
         return ERROR_INVALID_VERSION;
   }

   //Point to the next field
   data += n;
   length -= n;

   //Parse Extensions field
   error = x509ParseExtensions(data, length, &n, &certInfo->extensions);
   //Any parsing error?
   if(error)
      return error;

   //The Extensions field is optional
   if(n > 0)
   {
      //This field must only appear if the version is 3
      if(certInfo->version < X509_VERSION_3)
         return ERROR_INVALID_VERSION;
   }

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse Version field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] version Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509Version *version)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing Version...\r\n");

   //Explicit tagging shall be used to encode version
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);

   //Invalid tag?
   if(error)
   {
      //Assume X.509 version 1 format
      *version = X509_VERSION_1;
      //Skip the current field
      *totalLength = 0;

      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Read the inner tag
   error = asn1ReadInt32(tag.value, tag.length, &tag, &value);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Check version field
   if(value > X509_VERSION_3)
      return ERROR_INVALID_VERSION;

   //Save certificate version
   *version = (X509Version) value;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse SerialNumber field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] serialNumber Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSerialNumber(const uint8_t *data, size_t length,
   size_t *totalLength, X509SerialNumber *serialNumber)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing SerialNumber...\r\n");

   //Read the contents of the SerialNumber structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Check the length of the serial number
   if(tag.length < 1)
      return ERROR_INVALID_SYNTAX;

   //Non-conforming CAs may issue certificates with serial numbers that are
   //negative or zero. Certificate users should be prepared to gracefully
   //handle such certificates (refer to RFC 5280, section 4.1.2.2)
   serialNumber->data = tag.value;
   serialNumber->length = tag.length;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse Signature field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] signature Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSignature(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignatureAlgoId *signature)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing Signature...\r\n");

   //Read the contents of the Signature structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read signature algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the signature algorithm identifier
   signature->oid = tag.value;
   signature->oidLen = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSASSA-PSS algorithm identifier?
   if(!asn1CheckOid(&tag, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Read RSASSA-PSS parameters
      error = x509ParseRsaPssParameters(data, length, &signature->rsaPssParams);
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
 * @brief Parse RSASSA-PSS parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssParameters(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

#if(X509_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //The default hash algorithm is SHA-1 (refer to RFC 4055, section 3.1)
   rsaPssParams->hashAlgo = SHA1_OID;
   rsaPssParams->hashAlgoLen = sizeof(SHA1_OID);
#endif

   //The default length of the salt is 20 (refer to RFC 4055, section 3.1)
   rsaPssParams->saltLen = 20;

   //Read the contents of the structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Parse RSASSA-PSS parameters
   while(length > 0)
   {
      //Read current parameter
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //The tags in this sequence are explicit
      if(!asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0))
      {
         //Parse hashAlgorithm field
         error = x509ParseRsaPssHashAlgo(tag.value, tag.length, rsaPssParams);
         //Any error to report?
         if(error)
            return error;
      }
      else if(!asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 2))
      {
         //Parse saltLength field
         error = x509ParseRsaPssSaltLength(tag.value, tag.length, rsaPssParams);
         //Any error to report?
         if(error)
            return error;
      }

      //Next parameter
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse RSASSA-PSS hash algorithm
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssHashAlgo(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Read the contents of the structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read hash algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the hash algorithm identifier
   rsaPssParams->hashAlgo = tag.value;
   rsaPssParams->hashAlgoLen = tag.length;

   //No error to report
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse RSASSA-PSS salt length
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPssParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPssSaltLength(const uint8_t *data, size_t length,
   X509RsaPssParameters *rsaPssParams)
{
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   int32_t saltLen;
   Asn1Tag tag;

   //Read the saltLength field
   error = asn1ReadInt32(data, length, &tag, &saltLen);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Sanity check
   if(saltLen < 0)
      return ERROR_INVALID_SYNTAX;

   //Save the length of the salt
   rsaPssParams->saltLen = saltLen;

   //No error to report
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse Name structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] name Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseName(const uint8_t *data, size_t length,
   size_t *totalLength, X509Name *name)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509NameAttribute nameAttribute;

   //Debug message
   TRACE_DEBUG("    Parsing Name...\r\n");

   //Read the contents of the Name structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   name->rawData = data;
   name->rawDataLen = tag.totalLength;

   //The Name describes a hierarchical name composed of attributes
   data = tag.value;
   length = tag.length;

   //Loop through all the attributes
   while(length > 0)
   {
      //Read current attribute
      error = x509ParseNameAttribute(data, length, &n, &nameAttribute);
      //Any error to report?
      if(error)
         return error;

      //Common Name attribute found?
      if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_COMMON_NAME_OID, sizeof(X509_COMMON_NAME_OID)))
      {
         name->commonName = nameAttribute.value;
         name->commonNameLen = nameAttribute.valueLen;
      }
      //Surname attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_SURNAME_OID, sizeof(X509_SURNAME_OID)))
      {
         name->surname = nameAttribute.value;
         name->surnameLen = nameAttribute.valueLen;
      }
      //Serial Number attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_SERIAL_NUMBER_OID, sizeof(X509_SERIAL_NUMBER_OID)))
      {
         name->serialNumber = nameAttribute.value;
         name->serialNumberLen = nameAttribute.valueLen;
      }
      //Country Name attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_COUNTRY_NAME_OID, sizeof(X509_COUNTRY_NAME_OID)))
      {
         name->countryName = nameAttribute.value;
         name->countryNameLen = nameAttribute.valueLen;
      }
      //Locality Name attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_LOCALITY_NAME_OID, sizeof(X509_LOCALITY_NAME_OID)))
      {
         name->localityName = nameAttribute.value;
         name->localityNameLen = nameAttribute.valueLen;
      }
      //State Or Province Name attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_STATE_OR_PROVINCE_NAME_OID, sizeof(X509_STATE_OR_PROVINCE_NAME_OID)))
      {
         name->stateOrProvinceName = nameAttribute.value;
         name->stateOrProvinceNameLen = nameAttribute.valueLen;
      }
      //Organization Name attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_ORGANIZATION_NAME_OID, sizeof(X509_ORGANIZATION_NAME_OID)))
      {
         name->organizationName = nameAttribute.value;
         name->organizationNameLen = nameAttribute.valueLen;
      }
      //Organizational Unit Name attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_ORGANIZATIONAL_UNIT_NAME_OID, sizeof(X509_ORGANIZATIONAL_UNIT_NAME_OID)))
      {
         name->organizationalUnitName = nameAttribute.value;
         name->organizationalUnitNameLen = nameAttribute.valueLen;
      }
      //Title attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_TITLE_OID, sizeof(X509_TITLE_OID)))
      {
         name->title = nameAttribute.value;
         name->titleLen = nameAttribute.valueLen;
      }
      //Name attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_NAME_OID, sizeof(X509_NAME_OID)))
      {
         name->name = nameAttribute.value;
         name->nameLen = nameAttribute.valueLen;
      }
      //Given Name attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_GIVEN_NAME_OID, sizeof(X509_GIVEN_NAME_OID)))
      {
         name->givenName = nameAttribute.value;
         name->givenNameLen = nameAttribute.valueLen;
      }
      //Initials attribute OID (2.5.4.43)
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_INITIALS_OID, sizeof(X509_INITIALS_OID)))
      {
         name->initials = nameAttribute.value;
         name->initialsLen = nameAttribute.valueLen;
      }
      //Generation Qualifier attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_GENERATION_QUALIFIER_OID, sizeof(X509_GENERATION_QUALIFIER_OID)))
      {
         name->generationQualifier = nameAttribute.value;
         name->generationQualifierLen = nameAttribute.valueLen;
      }
      //DN Qualifier attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_DN_QUALIFIER_OID, sizeof(X509_DN_QUALIFIER_OID)))
      {
         name->dnQualifier = nameAttribute.value;
         name->dnQualifierLen = nameAttribute.valueLen;
      }
      //Pseudonym attribute found?
      else if(!oidComp(nameAttribute.type, nameAttribute.typeLen,
         X509_PSEUDONYM_OID, sizeof(X509_PSEUDONYM_OID)))
      {
         name->pseudonym = nameAttribute.value;
         name->pseudonymLen = nameAttribute.valueLen;
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

   //Name field successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse name attribute
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] nameAttribute Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseNameAttribute(const uint8_t *data, size_t length,
   size_t *totalLength, X509NameAttribute *nameAttribute)
{
   error_t error;
   Asn1Tag tag;

   //Attributes are encapsulated within a set
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET);
   //Invalid tag?
   if(error)
      return error;

   //Save the total length of the attribute
   *totalLength = tag.totalLength;

   //Read the first field of the set
   error = asn1ReadSequence(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read attribute type
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save attribute type
   nameAttribute->type = tag.value;
   nameAttribute->typeLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read attribute value
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save attribute value
   nameAttribute->value = (char_t *) tag.value;
   nameAttribute->valueLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Validity structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] validity Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseValidity(const uint8_t *data, size_t length,
   size_t *totalLength, X509Validity *validity)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing Validity...\r\n");

   //Read the contents of the Validity structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the very first field of the sequence
   data = tag.value;
   length = tag.length;

   //The NotBefore field may be encoded as UTCTime or GeneralizedTime
   error = x509ParseTime(data, length, &n, &validity->notBefore);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The NotAfter field may be encoded as UTCTime or GeneralizedTime
   error = x509ParseTime(data, length, &n, &validity->notAfter);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Validity field successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse UTCTime or GeneralizedTime field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] dateTime date resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseTime(const uint8_t *data, size_t length,
   size_t *totalLength, DateTime *dateTime)
{
   error_t error;
   uint_t value;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing Time...\r\n");

   //Read current ASN.1 tag
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The date may be encoded as UTCTime or GeneralizedTime
   if(!asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_UTC_TIME))
   {
      //Check the length of the UTCTime field
      if(tag.length != 13)
         return ERROR_INVALID_SYNTAX;

      //The UTCTime uses a 2-digit representation of the year
      error = x509ReadInt(tag.value, 2, &value);
      //Any error to report?
      if(error)
         return error;

      //If YY is greater than or equal to 50, the year shall be interpreted
      //as 19YY. If YY is less than 50, the year shall be interpreted as 20YY
      if(value >= 50)
         dateTime->year = 1900 + value;
      else
         dateTime->year = 2000 + value;

      //Point to the next field
      data = tag.value + 2;
   }
   else if(!asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_GENERALIZED_TIME))
   {
      //Check the length of the GeneralizedTime field
      if(tag.length != 15)
         return ERROR_INVALID_SYNTAX;

      //The GeneralizedTime uses a 4-digit representation of the year
      error = x509ReadInt(tag.value, 4, &value);
      //Any error to report?
      if(error)
         return error;

      //Save the resulting value
      dateTime->year = value;

      //Point to the next field
      data = tag.value + 4;
   }
   else
   {
      //The tag does not contain a valid date
      return ERROR_FAILURE;
   }

   //Month
   error = x509ReadInt(data, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->month = value;

   //Day
   error = x509ReadInt(data + 2, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->day = value;

   //Hours
   error = x509ReadInt(data + 4, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->hours = value;

   //Minutes
   error = x509ReadInt(data + 6, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->minutes = value;

   //Seconds
   error = x509ReadInt(data + 8, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //The encoding shall terminate with a "Z"
   if(data[10] != 'Z')
      return ERROR_INVALID_SYNTAX;

   //Save the resulting value
   dateTime->seconds = value;

   //Milliseconds
   dateTime->milliseconds = 0;

   //UTCTime or GeneralizedTime field successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse SubjectPublicKeyInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] subjectPublicKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectPublicKeyInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *subjectPublicKeyInfo)
{
   error_t error;
   size_t n;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing SubjectPublicKeyInfo...\r\n");

   //Read SubjectPublicKeyInfo field
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   subjectPublicKeyInfo->rawData = data;
   subjectPublicKeyInfo->rawDataLen = tag.totalLength;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read AlgorithmIdentifier field
   error = x509ParseAlgorithmIdentifier(data, length, &n, subjectPublicKeyInfo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The SubjectPublicKey structure is encapsulated within a bit string
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
   //Invalid tag?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(tag.length < 1 || tag.value[0] != 0x00)
      return ERROR_FAILURE;

   //Retrieve signature algorithm identifier
   oid = subjectPublicKeyInfo->oid;
   oidLen = subjectPublicKeyInfo->oidLen;

#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!oidComp(oid, oidLen, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //Read RSAPublicKey structure
      error = x509ParseRsaPublicKey(tag.value + 1, tag.length - 1,
         &subjectPublicKeyInfo->rsaPublicKey);
   }
   else
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA-PSS algorithm identifier?
   if(!oidComp(oid, oidLen, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //Read RSAPublicKey structure
      error = x509ParseRsaPublicKey(tag.value + 1, tag.length - 1,
         &subjectPublicKeyInfo->rsaPublicKey);
   }
   else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(oid, oidLen, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DSAPublicKey structure
      error = x509ParseDsaPublicKey(tag.value + 1, tag.length - 1,
         &subjectPublicKeyInfo->dsaPublicKey);
   }
   else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!oidComp(oid, oidLen, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(tag.value + 1, tag.length - 1,
         &subjectPublicKeyInfo->ecPublicKey);
   }
   else
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(!oidComp(oid, oidLen, X25519_OID, sizeof(X25519_OID)) ||
      !oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(tag.value + 1, tag.length - 1,
         &subjectPublicKeyInfo->ecPublicKey);
   }
   else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(!oidComp(oid, oidLen, X448_OID, sizeof(X448_OID)) ||
      !oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(tag.value + 1, tag.length - 1,
         &subjectPublicKeyInfo->ecPublicKey);
   }
   else
#endif
   //The certificate does not contain any valid public key...
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse AlgorithmIdentifier structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] subjectPublicKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAlgorithmIdentifier(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *subjectPublicKeyInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing AlgorithmIdentifier...\r\n");

   //Read AlgorithmIdentifier field
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read algorithm identifier (OID)
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the algorithm identifier
   subjectPublicKeyInfo->oid = tag.value;
   subjectPublicKeyInfo->oidLen = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!asn1CheckOid(&tag, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //RSA does not require any additional parameters
      error = NO_ERROR;
   }
   else
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA-PSS algorithm identifier?
   if(!asn1CheckOid(&tag, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //RSA-PSS does not require any additional parameters
      error = NO_ERROR;
   }
   else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!asn1CheckOid(&tag, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DsaParameters structure
      error = x509ParseDsaParameters(data, length,
         &subjectPublicKeyInfo->dsaParams);
   }
   else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECParameters structure
      error = x509ParseEcParameters(data, length,
         &subjectPublicKeyInfo->ecParams);
   }
   else
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(!asn1CheckOid(&tag, X25519_OID, sizeof(X25519_OID)) ||
      !asn1CheckOid(&tag, ED25519_OID, sizeof(ED25519_OID)))
   {
      //For all of the OIDs, the parameters are absent
      error = NO_ERROR;
   }
   else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(!asn1CheckOid(&tag, X448_OID, sizeof(X448_OID)) ||
      !asn1CheckOid(&tag, ED448_OID, sizeof(ED448_OID)))
   {
      //For all of the OIDs, the parameters are absent
      error = NO_ERROR;
   }
   else
#endif
   //The certificate does not contain any valid public key...
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse RSAPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPublicKey(const uint8_t *data, size_t length,
   X509RsaPublicKey *rsaPublicKey)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing RSAPublicKey...\r\n");

   //Read RSAPublicKey structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read Modulus field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Get the modulus
   rsaPublicKey->n = tag.value;
   rsaPublicKey->nLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PublicExponent field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Get the public exponent
   rsaPublicKey->e = tag.value;
   rsaPublicKey->eLen = tag.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse DSA domain parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaParameters(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing DSAParameters...\r\n");

   //Read DSAParameters structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read the parameter p
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter p
   dsaParams->p = tag.value;
   dsaParams->pLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the parameter q
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter q
   dsaParams->q = tag.value;
   dsaParams->qLen = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the parameter g
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter g
   dsaParams->g = tag.value;
   dsaParams->gLen = tag.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse DSAPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaPublicKey(const uint8_t *data, size_t length,
   X509DsaPublicKey *dsaPublicKey)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing DSAPublicKey...\r\n");

   //Read DSAPublicKey structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the DSA public value
   dsaPublicKey->y = tag.value;
   dsaPublicKey->yLen = tag.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse ECParameters structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcParameters(const uint8_t *data, size_t length,
   X509EcParameters *ecParams)
{
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing ECParameters...\r\n");

   //Read namedCurve field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The namedCurve field identifies all the required values for a particular
   //set of elliptic curve domain parameters to be represented by an object
   //identifier
   ecParams->namedCurve = tag.value;
   ecParams->namedCurveLen = tag.length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse ECPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcPublicKey(const uint8_t *data, size_t length,
   X509EcPublicKey *ecPublicKey)
{
#if ((X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED) || \
   (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED) || \
   (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED))
   //Debug message
   TRACE_DEBUG("      Parsing ECPublicKey...\r\n");

   //Make sure the EC public key is valid
   if(length == 0)
      return ERROR_BAD_CERTIFICATE;

   //Save the EC public key
   ecPublicKey->q = data;
   ecPublicKey->qLen = length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse IssuerUniqueID structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @return Error code
 **/

error_t x509ParseIssuerUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength)
{
   error_t error;
   Asn1Tag tag;

   //No more data to process?
   if(length == 0)
   {
      //The IssuerUniqueID field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Implicit tagging is used to encode the IssuerUniqueID field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 1);
   //Invalid tag?
   if(error)
   {
      //The IssuerUniqueID field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Debug message
   TRACE_DEBUG("    Parsing IssuerUniqueID...\r\n");

   //Conforming applications should be capable of parsing certificates that
   //include unique identifiers, but there are no processing requirements
   //associated with the unique identifiers
   return NO_ERROR;
}


/**
 * @brief Parse SubjectUniqueID structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @return Error code
 **/

error_t x509ParseSubjectUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength)
{
   error_t error;
   Asn1Tag tag;

   //No more data to process?
   if(length == 0)
   {
      //The SubjectUniqueID field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Implicit tagging is used to encode the SubjectUniqueID field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 2);
   //Invalid tag?
   if(error)
   {
      //The SubjectUniqueID field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Debug message
   TRACE_DEBUG("    Parsing SubjectUniqueID...\r\n");

   //Conforming applications should be capable of parsing certificates that
   //include unique identifiers, but there are no processing requirements
   //associated with the unique identifiers
   return NO_ERROR;
}


/**
 * @brief Parse X.509 certificate extensions
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] extensions Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509Extensions *extensions)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //No more data to process?
   if(length == 0)
   {
      //The Extensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Explicit tagging is used to encode the Extensions field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 3);
   //Invalid tag?
   if(error)
   {
      //The Extensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Debug message
   TRACE_DEBUG("    Parsing Extensions...\r\n");

   //This field is a sequence of one or more certificate extensions
   error = asn1ReadSequence(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   extensions->rawData = tag.value;
   extensions->rawDataLen = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Loop through the extensions
   while(length > 0)
   {
      //Each extension includes an OID and a value
      error = x509ParseExtension(data, length, &n, &extension);
      //Any error to report?
      if(error)
         return error;

      //BasicConstraints extension found?
      if(!oidComp(extension.oid, extension.oidLen,
         X509_BASIC_CONSTRAINTS_OID, sizeof(X509_BASIC_CONSTRAINTS_OID)))
      {
         //Parse BasicConstraints extension
         error = x509ParseBasicConstraints(extension.value, extension.valueLen,
            &extensions->basicConstraints);
      }
      //NameConstraints extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_NAME_CONSTRAINTS_OID, sizeof(X509_NAME_CONSTRAINTS_OID)))
      {
         //Parse NameConstraints extension
         error = x509ParseNameConstraints(extension.value, extension.valueLen,
            &extensions->nameConstraints);
      }
#if 0
      //PolicyConstraints extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_POLICY_CONSTRAINTS_OID, sizeof(X509_POLICY_CONSTRAINTS_OID)))
      {
         //Parse PolicyConstraints extension
         error = x509ParsePolicyConstraints(extension.value, extension.valueLen);
      }
      //PolicyMappings extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_POLICY_MAPPINGS_OID, sizeof(X509_POLICY_MAPPINGS_OID)))
      {
         //Parse PolicyMappings extension
         error = x509ParsePolicyMappings(extension.value, extension.valueLen);
      }
      //InhibitAnyPolicy extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_INHIBIT_ANY_POLICY_OID, sizeof(X509_INHIBIT_ANY_POLICY_OID)))
      {
         //Parse InhibitAnyPolicy extension
         error = x509ParseInhibitAnyPolicy(extension.value, extension.valueLen);
      }
#endif
      //KeyUsage extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_KEY_USAGE_OID, sizeof(X509_KEY_USAGE_OID)))
      {
         //Parse KeyUsage extension
         error = x509ParseKeyUsage(extension.value, extension.valueLen,
            &extensions->keyUsage);
      }
      //ExtendedKeyUsage extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_EXTENDED_KEY_USAGE_OID, sizeof(X509_EXTENDED_KEY_USAGE_OID)))
      {
         //Parse ExtendedKeyUsage extension
         error = x509ParseExtendedKeyUsage(extension.value, extension.valueLen,
            &extensions->extKeyUsage);
      }
      //SubjectAltName extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_SUBJECT_ALT_NAME_OID, sizeof(X509_SUBJECT_ALT_NAME_OID)))
      {
         //Parse SubjectAltName extension
         error = x509ParseSubjectAltName(extension.value, extension.valueLen,
            &extensions->subjectAltName);
      }
      //SubjectKeyIdentifier extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_SUBJECT_KEY_ID_OID, sizeof(X509_SUBJECT_KEY_ID_OID)))
      {
         //Parse SubjectKeyIdentifier extension
         error = x509ParseSubjectKeyId(extension.value, extension.valueLen,
            &extensions->subjectKeyId);
      }
      //AuthorityKeyIdentifier extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_AUTHORITY_KEY_ID_OID, sizeof(X509_AUTHORITY_KEY_ID_OID)))
      {
         //Parse AuthorityKeyIdentifier extension
         error = x509ParseAuthorityKeyId(extension.value, extension.valueLen,
            &extensions->authorityKeyId);
      }
      //NetscapeCertType extension found?
      else if(!oidComp(extension.oid, extension.oidLen,
         X509_NS_CERT_TYPE_OID, sizeof(X509_NS_CERT_TYPE_OID)))
      {
         //Parse NetscapeCertType extension
         error = x509ParseNsCertType(extension.value, extension.valueLen,
            &extensions->nsCertType);
      }
      //Unknown extension?
      else
      {
         //Check if the extension is marked as critical
         if(extension.critical)
         {
            //An application must reject the certificate if it encounters a
            //critical extension it does not recognize or a critical extension
            //that contains information that it cannot process
            error = ERROR_UNSUPPORTED_EXTENSION;
         }
      }

      //Any parsing error?
      if(error)
         return error;

      //Next extension
      data += n;
      length -= n;
   }

   //Check whether the keyCertSign bit is asserted
   if(extensions->keyUsage & X509_KEY_USAGE_KEY_CERT_SIGN)
   {
      //If the keyCertSign bit is asserted, then the cA bit in the basic
      //constraints extension must also be asserted (refer to RFC 5280,
      //section 4.2.1.3)
      if(!extensions->basicConstraints.cA)
         return ERROR_INVALID_SYNTAX;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse X.509 certificate extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] extension Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseExtension(const uint8_t *data, size_t length,
   size_t *totalLength, X509Extension *extension)
{
   error_t error;
   Asn1Tag tag;

   //The X.509 extension is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the X.509 extension
   *totalLength = tag.totalLength;

   //Each extension includes an OID and a value
   data = tag.value;
   length = tag.length;

   //Read extension OID
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the object identifier
   extension->oid = tag.value;
   extension->oidLen = tag.length;

   //Next item
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the Critical flag (if present)
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BOOLEAN);

   //Check whether the Critical field is present
   if(!error)
   {
      //Make sure the length of the boolean is valid
      if(tag.length != 1)
         return ERROR_INVALID_LENGTH;

      //Each extension in a certificate is designated as either critical
      //or non-critical
      extension->critical = tag.value[0] ? TRUE : FALSE;

      //Next item
      data += tag.totalLength;
      length -= tag.totalLength;
   }
   else
   {
      //The extension is considered as non-critical
      extension->critical = FALSE;
   }

   //The extension value is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the value of the extension
   extension->value = tag.value;
   extension->valueLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse BasicConstraints extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] basicConstraints Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseBasicConstraints(const uint8_t *data, size_t length,
   X509BasicConstraints *basicConstraints)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing BasicConstraints...\r\n");

   //The BasicConstraints structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //The cA field is optional
   if(length > 0)
   {
      //The cA boolean indicates whether the certified public key may be used
      //to verify certificate signatures
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BOOLEAN);

      //Check status code
      if(!error)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_LENGTH;

         //Get boolean value
         basicConstraints->cA = tag.value[0] ? TRUE : FALSE;

         //Point to the next item
         data += tag.totalLength;
         length -= tag.totalLength;
      }
   }

   //The pathLenConstraint field is optional
   if(length > 0)
   {
      //Read the pathLenConstraint field
      error = asn1ReadInt32(data, length, &tag, &value);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //The pathLenConstraint field is meaningful only if the cA boolean is
      //asserted (refer to RFC 5280, section 4.2.1.9)
      if(!basicConstraints->cA)
         return ERROR_INVALID_SYNTAX;

      //Where it appears, the pathLenConstraint field must be greater than or
      //equal to zero (refer to RFC 5280, section 4.2.1.9)
      if(value < 0)
         return ERROR_INVALID_SYNTAX;

      //The pathLenConstraint field gives the maximum number of non-self-issued
      //intermediate certificates that may follow this certificate in a valid
      //certification path
      basicConstraints->pathLenConstraint = value;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse NameConstraints extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] nameConstraints Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseNameConstraints(const uint8_t *data, size_t length,
   X509NameConstraints *nameConstraints)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing NameConstraints...\r\n");

   //The NameConstraints structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Conforming CAs must not issue certificates where name constraints is an
   //empty sequence (refer to RFC 5280, section 4.2.1.10)
   if(tag.length == 0)
      return ERROR_INVALID_SYNTAX;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //The name constraints extension indicates a name space within which all
   //subject names in subsequent certificates in a certification path must
   //be located
   while(length > 0)
   {
      //Parse GeneralSubtrees field
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Explicit tagging shall be used to encode the GeneralSubtrees field
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //The sequence cannot be empty (refer to RFC 5280, section 4.2.1.10)
      if(tag.length == 0)
         return ERROR_INVALID_SYNTAX;

      //Restrictions are defined in terms of permitted or excluded name subtrees
      if(tag.objType == 0)
      {
         //Parse the permittedSubtrees field
         error = x509ParseGeneralSubtrees(tag.value, tag.length);
         //Any error to report?
         if(error)
            return error;

         //Raw contents of the ASN.1 sequence
         nameConstraints->permittedSubtrees = tag.value;
         nameConstraints->permittedSubtreesLen = tag.length;
      }
      else if(tag.objType == 1)
      {
         //Parse the excludedSubtrees field
         error = x509ParseGeneralSubtrees(tag.value, tag.length);
         //Any error to report?
         if(error)
            return error;

         //Raw contents of the ASN.1 sequence
         nameConstraints->excludedSubtrees = tag.value;
         nameConstraints->excludedSubtreesLen = tag.length;
      }
      else
      {
         //Report an error
         return ERROR_INVALID_TYPE;
      }

      //Next item
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PolicyConstraints extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t x509ParsePolicyConstraints(const uint8_t *data, size_t length)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing PolicyConstraints...\r\n");

   //The PolicyConstraints structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Conforming CAs must not issue certificates where policy constraints is an
   //empty sequence (refer to RFC 5280, section 4.2.1.11)
   if(tag.length == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PolicyMappings extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t x509ParsePolicyMappings(const uint8_t *data, size_t length)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing PolicyMappings...\r\n");

   //The PolicyMappings structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The sequence cannot be empty (refer to RFC 5280, section 4.2.1.5)
   if(tag.length == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse InhibitAnyPolicy extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t x509ParseInhibitAnyPolicy(const uint8_t *data, size_t length)
{
   //Debug message
   TRACE_DEBUG("      Parsing InhibitAnyPolicy...\r\n");

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse KeyUsage extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] keyUsage Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseKeyUsage(const uint8_t *data, size_t length,
   uint16_t *keyUsage)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing KeyUsage...\r\n");

   //A certificate must not include more than one instance of a particular
   //extension (refer to RFC 5280, section 4.2)
   if(*keyUsage != 0)
      return ERROR_INVALID_SYNTAX;

   //The key usage extension defines the purpose of the key contained in the
   //certificate
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
   //Invalid tag?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(tag.length < 1)
      return ERROR_INVALID_SYNTAX;

   //Sanity check
   if(tag.value[0] >= 8)
      return ERROR_INVALID_SYNTAX;

   //Clear bit string
   *keyUsage = 0;

   //Read bits b0 to b7
   if(tag.length >= 2)
      *keyUsage |= reverseInt8(tag.value[1]);

   //Read bits b8 to b15
   if(tag.length >= 3)
      *keyUsage |= reverseInt8(tag.value[2]) << 8;

   //When the key usage extension appears in a certificate, at least one of
   //the bits must be set to 1 (refer to RFC 5280, section 4.2.1.3)
   if(*keyUsage == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ExtendedKeyUsage extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] extKeyUsage Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseExtendedKeyUsage(const uint8_t *data, size_t length,
   uint8_t *extKeyUsage)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing ExtendedKeyUsage...\r\n");

   //A certificate must not include more than one instance of a particular
   //extension (refer to RFC 5280, section 4.2)
   if(*extKeyUsage != 0)
      return ERROR_INVALID_SYNTAX;

   //The ExtendedKeyUsage structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The sequence cannot be empty (refer to RFC 5280, section 4.2.1.12)
   if(tag.length == 0)
      return ERROR_INVALID_SYNTAX;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //This extension indicates one or more purposes for which the certified
   //public key may be used
   while(length > 0)
   {
      //Read KeyPurposeId field
      error = asn1ReadOid(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //anyExtendedKeyUsage?
      if(!oidComp(tag.value, tag.length,
         X509_ANY_EXT_KEY_USAGE_OID, sizeof(X509_ANY_EXT_KEY_USAGE_OID)))
      {
         //If a CA includes extended key usages to satisfy such applications,
         //but does not wish to restrict usages of the key, the CA can include
         //the special KeyPurposeId anyExtendedKeyUsage
         *extKeyUsage |= X509_EXT_KEY_USAGE_ANY;
      }
      //id-kp-serverAuth?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_SERVER_AUTH_OID, sizeof(X509_KP_SERVER_AUTH_OID)))
      {
         //TLS WWW server authentication
         *extKeyUsage |= X509_EXT_KEY_USAGE_SERVER_AUTH;
      }
      //id-kp-clientAuth?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_CLIENT_AUTH_OID, sizeof(X509_KP_CLIENT_AUTH_OID)))
      {
         //TLS WWW client authentication
         *extKeyUsage |= X509_EXT_KEY_USAGE_CLIENT_AUTH;
      }
      //id-kp-codeSigning?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_CODE_SIGNING_OID, sizeof(X509_KP_CODE_SIGNING_OID)))
      {
         //Signing of downloadable executable code
         *extKeyUsage |= X509_EXT_KEY_USAGE_CODE_SIGNING;
      }
      //id-kp-emailProtection?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_EMAIL_PROTECTION_OID, sizeof(X509_KP_EMAIL_PROTECTION_OID)))
      {
         //Email protection
         *extKeyUsage |= X509_EXT_KEY_USAGE_EMAIL_PROTECTION;
      }
      //id-kp-timeStamping?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_TIME_STAMPING_OID, sizeof(X509_KP_TIME_STAMPING_OID)))
      {
         //Binding the hash of an object to a time
         *extKeyUsage |= X509_EXT_KEY_USAGE_TIME_STAMPING;
      }
      //id-kp-OCSPSigning?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_OCSP_SIGNING_OID, sizeof(X509_KP_OCSP_SIGNING_OID)))
      {
         //Signing OCSP responses
         *extKeyUsage |= X509_EXT_KEY_USAGE_OCSP_SIGNING;
      }
      //Unknown key purpose?
      else
      {
         //Discard KeyPurposeId field
      }

      //Next item
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SubjectAltName extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] subjectAltName Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectAltName(const uint8_t *data, size_t length,
   X509SubjectAltName *subjectAltName)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509GeneralName generalName;

   //Debug message
   TRACE_DEBUG("      Parsing SubjectAltName...\r\n");

   //The SubjectAltName structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   subjectAltName->rawData = tag.value;
   subjectAltName->rawDataLen = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //The subject alternative name extension allows identities to be bound to the
   //subject of the certificate. These identities may be included in addition
   //to or in place of the identity in the subject field of the certificate
   for(i = 0; length > 0; i++)
   {
      //Parse GeneralName field
      error = x509ParseGeneralName(data, length, &n, &generalName);
      //Any error to report?
      if(error)
         return error;

      //Sanity check
      if(i < X509_MAX_SUBJECT_ALT_NAMES)
      {
         //Save subject alternative name
         subjectAltName->generalNames[i] = generalName;
      }

      //Next item
      data += n;
      length -= n;
   }

   //If the SubjectAltName extension is present, the sequence must contain at
   //least one entry (refer to RFC 5280, section 4.2.1.6)
   if(i == 0)
      return ERROR_INVALID_SYNTAX;

   //Save the number of subject alternative names
   subjectAltName->numGeneralNames = MIN(i, X509_MAX_SUBJECT_ALT_NAMES);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse GeneralSubtrees field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t x509ParseGeneralSubtrees(const uint8_t *data, size_t length)
{
   error_t error;
   size_t n;
   X509GeneralName generalName;

   //Loop through the list of GeneralSubtree fields
   while(length > 0)
   {
      //Parse current GeneralSubtree field
      error = x509ParseGeneralSubtree(data, length, &n, &generalName);
      //Any error to report?
      if(error)
         return error;

      //Next item
      data += n;
      length -= n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse GeneralSubtree field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] generalName Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseGeneralSubtree(const uint8_t *data, size_t length,
   size_t *totalLength, X509GeneralName *generalName)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The GeneralSubtrees structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Parse GeneralName field
   error = x509ParseGeneralName(tag.value, tag.length, &n, generalName);

   //Discard minimum and maximum fields
   return error;
}


/**
 * @brief Parse GeneralName field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] generalName Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseGeneralName(const uint8_t *data, size_t length,
   size_t *totalLength, X509GeneralName *generalName)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing GeneralName...\r\n");

   //Read current item
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Explicit tagging shall be used to encode the subject alternative name
   if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
      return ERROR_INVALID_CLASS;

   //Conforming CAs must not issue certificates with subjectAltNames containing
   //empty GeneralName fields (refer to RFC 5280, section 4.2.1.6)
   if(tag.length == 0)
      return ERROR_INVALID_SYNTAX;

   //Save subject alternative name
   generalName->type = (X509GeneralNameType) tag.objType;
   generalName->value = (char_t *) tag.value;
   generalName->length = tag.length;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SubjectKeyIdentifier extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] subjectKeyId Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectKeyId(const uint8_t *data, size_t length,
   X509SubjectKeyId *subjectKeyId)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing SubjectKeyIdentifier...\r\n");

   //The subject key identifier extension provides a means of identifying
   //certificates that contain a particular public key
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the subject key identifier
   subjectKeyId->value = tag.value;
   subjectKeyId->length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse AuthorityKeyIdentifier extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] authorityKeyId Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAuthorityKeyId(const uint8_t *data, size_t length,
   X509AuthorityKeyId *authorityKeyId)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing AuthorityKeyIdentifier...\r\n");

   //The AuthorityKeyIdentifier structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Parse the content of the sequence
   while(length > 0)
   {
      //Read current item
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Explicit tagging shall be used to encode the authority key identifier
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //keyIdentifier object found?
      if(tag.objType == 0)
      {
         //Save the authority key identifier
         authorityKeyId->value = tag.value;
         authorityKeyId->length = tag.length;
      }

      //Next item
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse NetscapeCertType extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] nsCertType Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseNsCertType(const uint8_t *data, size_t length,
   uint8_t *nsCertType)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing NetscapeCertType...\r\n");

   //The NetscapeCertType extension limit the use of a certificate
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
   //Invalid tag?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(tag.length < 1)
      return ERROR_INVALID_SYNTAX;

   //Sanity check
   if(tag.value[0] >= 8)
      return ERROR_INVALID_SYNTAX;

   //Clear bit string
   *nsCertType = 0;

   //Read bits b0 to b7
   if(tag.length >= 2)
      *nsCertType |= reverseInt8(tag.value[1]);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SignatureAlgorithm structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] signatureAlgo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSignatureAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignatureAlgoId *signatureAlgo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing SignatureAlgorithm...\r\n");

   //Read the contents of the SignatureAlgorithm field
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Read the inner tag
   error = asn1ReadTag(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //This field must contain the same algorithm identifier as the signature
   //field in the TBSCertificate sequence
   error = asn1CheckOid(&tag, signatureAlgo->oid, signatureAlgo->oidLen);
   //Invalid tag?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SignatureValue field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] signatureValue Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSignatureValue(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignatureValue *signatureValue)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing SignatureValue...\r\n");

   //Read the contents of the SignatureValue structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
   //Invalid tag?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes
   //the number of unused bits in the final subsequent octet
   if(tag.length < 1 || tag.value[0] != 0x00)
      return ERROR_FAILURE;

   //Get the signature value
   signatureValue->data = tag.value + 1;
   signatureValue->length = tag.length - 1;

   //Successful processing
   return NO_ERROR;
}

#endif
