/**
 * @file x509_cert_parse.c
 * @brief X.509 certificate parsing
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
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
 * @version 1.8.0
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
   //Failed to parse Version field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read SerialNumber field
   error = x509ParseSerialNumber(data, length, &n, &certInfo->serialNumber);
   //Failed to parse SerialNumber field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read Signature field
   error = x509ParseSignature(data, length, &n, &certInfo->signatureAlgo);
   //Failed to parse Signature field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read Issuer field
   error = x509ParseName(data, length, &n, &certInfo->issuer);
   //Failed to parse Issuer field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read Validity field
   error = x509ParseValidity(data, length, &n, &certInfo->validity);
   //Failed to parse Validity field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read Subject field
   error = x509ParseName(data, length, &n, &certInfo->subject);
   //Failed to parse Subject field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read SubjectPublicKeyInfo field
   error = x509ParseSubjectPublicKeyInfo(data, length, &n, certInfo);
   //Failed to parse SubjectPublicKeyInfo field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read IssuerUniqueID field (optional)
   error = x509ParseIssuerUniqueId(data, length, &n, certInfo);
   //Failed to parse IssuerUniqueID field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read SubjectUniqueID field (optional)
   error = x509ParseSubjectUniqueId(data, length, &n, certInfo);
   //Failed to parse SubjectUniqueID field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read Extensions field (optional)
   error = x509ParseExtensions(data, length, &n, certInfo);
   //Failed to parse Extensions field?
   if(error)
      return error;

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

   //The tag does not match the criteria?
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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Conforming CAs must not use serialNumber values longer than 20 octets
   //(refer to RFC 5280, section 4.1.2.2)
   if(tag.length < 1 || tag.length > 20)
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
   size_t *totalLength, X509SignatureId *signature)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing Signature...\r\n");

   //Read the contents of the Signature structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Read the inner tag
   error = asn1ReadTag(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OBJECT_IDENTIFIER);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Get the signature algorithm identifier
   signature->data = tag.value;
   signature->length = tag.length;

   //Validity field successfully parsed
   return NO_ERROR;
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
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw ASN.1 sequence
   name->rawData = data;
   name->rawDataLen = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the total length of the attribute
   *totalLength = tag.totalLength;

   //Read the first field of the set
   error = asn1ReadTag(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read attribute type
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OBJECT_IDENTIFIER);
   //The tag does not match the criteria?
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
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectPublicKeyInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing SubjectPublicKeyInfo...\r\n");

   //Read SubjectPublicKeyInfo field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read AlgorithmIdentifier field
   error = x509ParseAlgorithmIdentifier(data, length, &n, certInfo);
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
   //The tag does not match the criteria?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(tag.length < 1 || tag.value[0] != 0x00)
      return ERROR_FAILURE;

#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!oidComp(certInfo->subjectPublicKeyInfo.oid, certInfo->subjectPublicKeyInfo.oidLen,
      RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //Read RSAPublicKey structure
      error = x509ParseRsaPublicKey(tag.value + 1, tag.length - 1, certInfo);
   }
   else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(certInfo->subjectPublicKeyInfo.oid, certInfo->subjectPublicKeyInfo.oidLen,
      DSA_OID, sizeof(DSA_OID)))
   {
      //Read DSAPublicKey structure
      error = x509ParseDsaPublicKey(tag.value + 1, tag.length - 1, certInfo);
   }
   else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!oidComp(certInfo->subjectPublicKeyInfo.oid, certInfo->subjectPublicKeyInfo.oidLen,
      EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(tag.value + 1, tag.length - 1, certInfo);
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAlgorithmIdentifier(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing AlgorithmIdentifier...\r\n");

   //Read AlgorithmIdentifier field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read algorithm identifier (OID)
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OBJECT_IDENTIFIER);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the algorithm identifier
   certInfo->subjectPublicKeyInfo.oid = tag.value;
   certInfo->subjectPublicKeyInfo.oidLen = tag.length;

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
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!asn1CheckOid(&tag, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DsaParameters structure
      error = x509ParseDsaParameters(data, length, certInfo);
   }
   else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECParameters structure
      error = x509ParseEcParameters(data, length, certInfo);
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPublicKey(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing RSAPublicKey...\r\n");

   //Read RSAPublicKey structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Get the modulus
   certInfo->subjectPublicKeyInfo.rsaPublicKey.n = tag.value;
   certInfo->subjectPublicKeyInfo.rsaPublicKey.nLen = tag.length;

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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Get the public exponent
   certInfo->subjectPublicKeyInfo.rsaPublicKey.e = tag.value;
   certInfo->subjectPublicKeyInfo.rsaPublicKey.eLen = tag.length;

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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaParameters(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing DSAParameters...\r\n");

   //Read DSAParameters structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the parameter p
   certInfo->subjectPublicKeyInfo.dsaParams.p = tag.value;
   certInfo->subjectPublicKeyInfo.dsaParams.pLen = tag.length;

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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the parameter q
   certInfo->subjectPublicKeyInfo.dsaParams.q = tag.value;
   certInfo->subjectPublicKeyInfo.dsaParams.qLen = tag.length;

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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the parameter g
   certInfo->subjectPublicKeyInfo.dsaParams.g = tag.value;
   certInfo->subjectPublicKeyInfo.dsaParams.gLen = tag.length;

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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaPublicKey(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo)
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
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the DSA public value
   certInfo->subjectPublicKeyInfo.dsaPublicKey.y = tag.value;
   certInfo->subjectPublicKeyInfo.dsaPublicKey.yLen = tag.length;

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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcParameters(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo)
{
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing ECParameters...\r\n");

   //Read namedCurve field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OBJECT_IDENTIFIER);
   //The tag does not match the criteria?
   if(error)
      return error;

   //The namedCurve field identifies all the required values for a particular
   //set of elliptic curve domain parameters to be represented by an object
   //identifier
   certInfo->subjectPublicKeyInfo.ecParams.namedCurve = tag.value;
   certInfo->subjectPublicKeyInfo.ecParams.namedCurveLen = tag.length;

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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcPublicKey(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo)
{
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //Debug message
   TRACE_DEBUG("      Parsing ECPublicKey...\r\n");

   //Make sure the EC public key is valid
   if(!length)
      return ERROR_BAD_CERTIFICATE;

   //Save the EC public key
   certInfo->subjectPublicKeyInfo.ecPublicKey.q = data;
   certInfo->subjectPublicKeyInfo.ecPublicKey.qLen = length;

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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseIssuerUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //No more data to process?
   if(!length)
   {
      //The IssuerUniqueID field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Explicit tagging is used to encode the IssuerUniqueID field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 1);
   //The tag does not match the criteria?
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

   //This field must only appear if the version is 2 or 3
   if(certInfo->version < X509_VERSION_2)
      return ERROR_INVALID_VERSION;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SubjectUniqueID structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //No more data to process?
   if(!length)
   {
      //The SubjectUniqueID field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Explicit tagging is used to encode the SubjectUniqueID field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 2);
   //The tag does not match the criteria?
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

   //This field must only appear if the version is 2 or 3
   if(certInfo->version < X509_VERSION_2)
      return ERROR_INVALID_VERSION;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Extensions structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
   bool_t critical;
   const uint8_t *extensionData;
   size_t extensionLength;
   Asn1Tag tag;
   Asn1Tag oidTag;

   //No more data to process?
   if(!length)
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
   //The tag does not match the criteria?
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

   //This field must only appear if the version is 3
   if(certInfo->version < X509_VERSION_3)
      return ERROR_INVALID_VERSION;

   //Read inner tag
   error = asn1ReadTag(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

   //This field is a sequence of one or more certificate extensions
   data = tag.value;
   length = tag.length;

   //Loop through the extensions
   while(length > 0)
   {
      //Read current extension
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
      //The tag does not match the criteria?
      if(error)
         return error;

      //Point to the next extension
      data += tag.totalLength;
      length -= tag.totalLength;

      //Contents of the current extension
      extensionData = tag.value;
      extensionLength = tag.length;

      //Read the object identifier
      error = asn1ReadTag(extensionData, extensionLength, &oidTag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&oidTag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_OBJECT_IDENTIFIER);
      //The tag does not match the criteria?
      if(error)
         return error;

      //Next item
      extensionData += oidTag.totalLength;
      extensionLength -= oidTag.totalLength;

      //Read the Critical flag (if present)
      error = asn1ReadTag(extensionData, extensionLength, &tag);
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
         critical = tag.value[0] ? TRUE : FALSE;

         //Next item
         extensionData += tag.totalLength;
         extensionLength -= tag.totalLength;
      }
      else
      {
         //The extension is considered as non-critical
         critical = FALSE;
      }

      //The extension itself is encapsulated in an octet string
      error = asn1ReadTag(extensionData, extensionLength, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_OCTET_STRING);
      //The tag does not match the criteria?
      if(error)
         return error;

      //BasicConstraints extension found?
      if(!oidComp(oidTag.value, oidTag.length,
         X509_BASIC_CONSTRAINTS_OID, sizeof(X509_BASIC_CONSTRAINTS_OID)))
      {
         //Parse BasicConstraints extension
         error = x509ParseBasicConstraints(tag.value, tag.length, certInfo);
      }
      //NameConstraints extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_NAME_CONSTRAINTS_OID, sizeof(X509_NAME_CONSTRAINTS_OID)))
      {
         //Parse NameConstraints extension
         error = x509ParseNameConstraints(tag.value, tag.length, certInfo);
      }
#if 0
      //PolicyConstraints extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_POLICY_CONSTRAINTS_OID, sizeof(X509_POLICY_CONSTRAINTS_OID)))
      {
         //Parse PolicyConstraints extension
         error = x509ParsePolicyConstraints(tag.value, tag.length, certInfo);
      }
      //PolicyMappings extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_POLICY_MAPPINGS_OID, sizeof(X509_POLICY_MAPPINGS_OID)))
      {
         //Parse PolicyMappings extension
         error = x509ParsePolicyMappings(tag.value, tag.length, certInfo);
      }
      //InhibitAnyPolicy extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_INHIBIT_ANY_POLICY_OID, sizeof(X509_INHIBIT_ANY_POLICY_OID)))
      {
         //Parse InhibitAnyPolicy extension
         error = x509ParseInhibitAnyPolicy(tag.value, tag.length, certInfo);
      }
#endif
      //KeyUsage extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_KEY_USAGE_OID, sizeof(X509_KEY_USAGE_OID)))
      {
         //Parse KeyUsage extension
         error = x509ParseKeyUsage(tag.value, tag.length, certInfo);
      }
      //ExtendedKeyUsage extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_EXTENDED_KEY_USAGE_OID, sizeof(X509_EXTENDED_KEY_USAGE_OID)))
      {
         //Parse ExtendedKeyUsage extension
         error = x509ParseExtendedKeyUsage(tag.value, tag.length, certInfo);
      }
      //SubjectAltName extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_SUBJECT_ALT_NAME_OID, sizeof(X509_SUBJECT_ALT_NAME_OID)))
      {
         //Parse SubjectAltName extension
         error = x509ParseSubjectAltName(tag.value, tag.length, certInfo);
      }
      //SubjectKeyIdentifier extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_SUBJECT_KEY_ID_OID, sizeof(X509_SUBJECT_KEY_ID_OID)))
      {
         //Parse SubjectKeyIdentifier extension
         error = x509ParseSubjectKeyId(tag.value, tag.length, certInfo);
      }
      //AuthorityKeyIdentifier extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_AUTHORITY_KEY_ID_OID, sizeof(X509_AUTHORITY_KEY_ID_OID)))
      {
         //Parse AuthorityKeyIdentifier extension
         error = x509ParseAuthorityKeyId(tag.value, tag.length, certInfo);
      }
      //NetscapeCertType extension found?
      else if(!oidComp(oidTag.value, oidTag.length,
         X509_NS_CERT_TYPE_OID, sizeof(X509_NS_CERT_TYPE_OID)))
      {
         //Parse NetscapeCertType extension
         error = x509ParseNsCertType(tag.value, tag.length, certInfo);
      }
      //Unknown extension?
      else
      {
         //Check if the current extension is marked as critical
         if(critical)
         {
            //An application must reject the certificate if it encounters a
            //critical extension it does not recognize or a critical extension
            //that contains information that it cannot process
            error = ERROR_UNSUPPORTED_EXTENSION;
         }
      }

      //Any error to report?
      if(error)
         return error;
   }

   //Check wether the keyCertSign bit is asserted
   if(certInfo->extensions.keyUsage & X509_KEY_USAGE_KEY_CERT_SIGN)
   {
      //If the keyCertSign bit is asserted, then the cA bit in the basic
      //constraints extension must also be asserted (refer to RFC 5280,
      //section 4.2.1.3)
      if(!certInfo->extensions.basicConstraints.cA)
         return ERROR_INVALID_SYNTAX;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse BasicConstraints extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseBasicConstraints(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing BasicConstraints...\r\n");

   //The BasicConstraints structure shall contain a valid sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
         certInfo->extensions.basicConstraints.cA = tag.value[0] ? TRUE : FALSE;

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
      if(!certInfo->extensions.basicConstraints.cA)
         return ERROR_INVALID_SYNTAX;

      //Where it appears, the pathLenConstraint field must be greater than or
      //equal to zero (refer to RFC 5280, section 4.2.1.9)
      if(value < 0)
         return ERROR_INVALID_SYNTAX;

      //The pathLenConstraint field gives the maximum number of non-self-issued
      //intermediate certificates that may follow this certificate in a valid
      //certification path
      certInfo->extensions.basicConstraints.pathLenConstraint = value;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse NameConstraints extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseNameConstraints(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing NameConstraints...\r\n");

   //The NameConstraints structure shall contain a valid sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
         certInfo->extensions.nameConstraints.permittedSubtrees = tag.value;
         certInfo->extensions.nameConstraints.permittedSubtreesLen = tag.length;
      }
      else if(tag.objType == 1)
      {
         //Parse the excludedSubtrees field
         error = x509ParseGeneralSubtrees(tag.value, tag.length);
         //Any error to report?
         if(error)
            return error;

         //Raw contents of the ASN.1 sequence
         certInfo->extensions.nameConstraints.excludedSubtrees = tag.value;
         certInfo->extensions.nameConstraints.excludedSubtreesLen = tag.length;
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParsePolicyConstraints(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing PolicyConstraints...\r\n");

   //The PolicyConstraints structure shall contain a valid sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParsePolicyMappings(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing PolicyMappings...\r\n");

   //The PolicyMappings structure shall contain a valid sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseInhibitAnyPolicy(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseKeyUsage(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing KeyUsage...\r\n");

   //A certificate must not include more than one instance of a particular
   //extension (refer to RFC 5280, section 4.2)
   if(certInfo->extensions.keyUsage != 0)
      return ERROR_INVALID_SYNTAX;

   //The key usage extension defines the purpose of the key contained in the
   //certificate
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
   //The tag does not match the criteria?
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
   certInfo->extensions.keyUsage = 0;

   //Read bits b0 to b7
   if(tag.length >= 2)
      certInfo->extensions.keyUsage |= reverseInt8(tag.value[1]);

   //Read bits b8 to b15
   if(tag.length >= 3)
      certInfo->extensions.keyUsage |= reverseInt8(tag.value[2]) << 8;

   //When the key usage extension appears in a certificate, at least one of
   //the bits must be set to 1 (refer to RFC 5280, section 4.2.1.3)
   if(certInfo->extensions.keyUsage == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ExtendedKeyUsage extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseExtendedKeyUsage(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing ExtendedKeyUsage...\r\n");

   //A certificate must not include more than one instance of a particular
   //extension (refer to RFC 5280, section 4.2)
   if(certInfo->extensions.extKeyUsage != 0)
      return ERROR_INVALID_SYNTAX;

   //The ExtendedKeyUsage structure shall contain a valid sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_OBJECT_IDENTIFIER);
      //The tag does not match the criteria?
      if(error)
         return error;

      //anyExtendedKeyUsage?
      if(!oidComp(tag.value, tag.length,
         X509_ANY_EXT_KEY_USAGE_OID, sizeof(X509_ANY_EXT_KEY_USAGE_OID)))
      {
         //If a CA includes extended key usages to satisfy such applications,
         //but does not wish to restrict usages of the key, the CA can include
         //the special KeyPurposeId anyExtendedKeyUsage
         certInfo->extensions.extKeyUsage |= X509_EXT_KEY_USAGE_ANY;
      }
      //id-kp-serverAuth?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_SERVER_AUTH_OID, sizeof(X509_KP_SERVER_AUTH_OID)))
      {
         //TLS WWW server authentication
         certInfo->extensions.extKeyUsage |= X509_EXT_KEY_USAGE_SERVER_AUTH;
      }
      //id-kp-clientAuth?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_CLIENT_AUTH_OID, sizeof(X509_KP_CLIENT_AUTH_OID)))
      {
         //TLS WWW client authentication
         certInfo->extensions.extKeyUsage |= X509_EXT_KEY_USAGE_CLIENT_AUTH;
      }
      //id-kp-codeSigning?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_CODE_SIGNING_OID, sizeof(X509_KP_CODE_SIGNING_OID)))
      {
         //Signing of downloadable executable code
         certInfo->extensions.extKeyUsage |= X509_EXT_KEY_USAGE_CODE_SIGNING;
      }
      //id-kp-emailProtection?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_EMAIL_PROTECTION_OID, sizeof(X509_KP_EMAIL_PROTECTION_OID)))
      {
         //Email protection
         certInfo->extensions.extKeyUsage |= X509_EXT_KEY_USAGE_EMAIL_PROTECTION;
      }
      //id-kp-timeStamping?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_TIME_STAMPING_OID, sizeof(X509_KP_TIME_STAMPING_OID)))
      {
         //Binding the hash of an object to a time
         certInfo->extensions.extKeyUsage |= X509_EXT_KEY_USAGE_TIME_STAMPING;
      }
      //id-kp-OCSPSigning?
      else if(!oidComp(tag.value, tag.length,
         X509_KP_OCSP_SIGNING_OID, sizeof(X509_KP_OCSP_SIGNING_OID)))
      {
         //Signing OCSP responses
         certInfo->extensions.extKeyUsage |= X509_EXT_KEY_USAGE_OCSP_SIGNING;
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectAltName(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509SubjectAltName *subjectAltName;
   X509GeneralName generalName;

   //Debug message
   TRACE_DEBUG("      Parsing SubjectAltName...\r\n");

   //Point to the SubjectAltName extension
   subjectAltName = &certInfo->extensions.subjectAltName;

   //The SubjectAltName structure shall contain a valid sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectKeyId(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing SubjectKeyIdentifier...\r\n");

   //The subject key identifier extension provides a means of identifying
   //certificates that contain a particular public key
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the subject key identifier
   certInfo->extensions.subjectKeyId = tag.value;
   certInfo->extensions.subjectKeyIdLen = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse AuthorityKeyIdentifier extension
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAuthorityKeyId(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing AuthorityKeyIdentifier...\r\n");

   //The AuthorityKeyIdentifier structure shall contain a valid sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
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
         certInfo->extensions.authorityKeyId= tag.value;
         certInfo->extensions.authorityKeyIdLen = tag.length;
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseNsCertType(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo)
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
   //The tag does not match the criteria?
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
   certInfo->extensions.nsCertType = 0;

   //Read bits b0 to b7
   if(tag.length >= 2)
      certInfo->extensions.nsCertType |= reverseInt8(tag.value[1]);

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
   size_t *totalLength, X509SignatureId *signatureAlgo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing SignatureAlgorithm...\r\n");

   //Read the contents of the SignatureAlgorithm field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Read the inner tag
   error = asn1ReadTag(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //This field must contain the same algorithm identifier as the signature
   //field in the TBSCertificate sequence
   error = asn1CheckOid(&tag, signatureAlgo->data, signatureAlgo->length);
   //The tag does not match the criteria?
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
   //The tag does not match the criteria?
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
