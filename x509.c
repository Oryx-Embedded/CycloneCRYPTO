/**
 * @file x509.c
 * @brief X.509 certificate parsing and verification
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
 * @version 1.7.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include <string.h>
#include <ctype.h>
#include "crypto.h"
#include "x509.h"
#include "asn1.h"
#include "oid.h"
#include "rsa.h"
#include "dsa.h"
#include "ecdsa.h"
#include "md5.h"
#include "sha1.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)

//Common Name OID (2.5.4.3)
const uint8_t X509_COMMON_NAME_OID[3] = {0x55, 0x04, 0x03};
//Surname OID (2.5.4.4)
const uint8_t X509_SURNAME_OID[3] = {0x55, 0x04, 0x04};
//Serial Number OID (2.5.4.5)
const uint8_t X509_SERIAL_NUMBER_OID[3] = {0x55, 0x04, 0x05};
//Country Name OID (2.5.4.6)
const uint8_t X509_COUNTRY_NAME_OID[3] = {0x55, 0x04, 0x06};
//Locality Name OID (2.5.4.7)
const uint8_t X509_LOCALITY_NAME_OID[3] = {0x55, 0x04, 0x07};
//State Or Province Name OID (2.5.4.8)
const uint8_t X509_STATE_OR_PROVINCE_NAME_OID[] = {0x55, 0x04, 0x08};
//Organization Name OID (2.5.4.10)
const uint8_t X509_ORGANIZATION_NAME_OID[3] = {0x55, 0x04, 0x0A};
//Organizational Unit Name OID (2.5.4.11)
const uint8_t X509_ORGANIZATIONAL_UNIT_NAME_OID[3] = {0x55, 0x04, 0x0B};
//Title OID (2.5.4.12)
const uint8_t X509_TITLE_OID[3] = {0x55, 0x04, 0x0C};
//Name OID (2.5.4.41)
const uint8_t X509_NAME_OID[3] = {0x55, 0x04, 0x29};
//Given Name OID (2.5.4.42)
const uint8_t X509_GIVEN_NAME_OID[3] = {0x55, 0x04, 0x2A};
//Initials OID (2.5.4.43)
const uint8_t X509_INITIALS_OID[3] = {0x55, 0x04, 0x2B};
//Generation Qualifier OID (2.5.4.44)
const uint8_t X509_GENERATION_QUALIFIER_OID[3] = {0x55, 0x04, 0x2C};
//DN Qualifier OID (2.5.4.46)
const uint8_t X509_DN_QUALIFIER_OID[3] = {0x55, 0x04, 0x2E};
//Pseudonym OID (2.5.4.65)
const uint8_t X509_PSEUDONYM_OID[3] = {0x55, 0x04, 0x41};

//Subject Directory Attributes OID (2.5.29.9)
const uint8_t X509_SUBJECT_DIRECTORY_ATTR_OID[3] = {0x55, 0x1D, 0x09};
//Subject Key Identifier OID (2.5.29.14)
const uint8_t X509_SUBJECT_KEY_ID_OID[3] = {0x55, 0x1D, 0x0E};
//Key Usage OID (2.5.29.15)
const uint8_t X509_KEY_USAGE_OID[3] = {0x55, 0x1D, 0x0F};
//Subject Alternative Name OID (2.5.29.17)
const uint8_t X509_SUBJECT_ALT_NAME_OID[3] = {0x55, 0x1D, 0x11};
//Issuer Alternative Name OID (2.5.29.18)
const uint8_t X509_ISSUER_ALT_NAME_OID[3] = {0x55, 0x1D, 0x12};
//Basic Constraints OID (2.5.29.19)
const uint8_t X509_BASIC_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x13};
//Name Constraints OID (2.5.29.30)
const uint8_t X509_NAME_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x1E};
//CRL Distribution Points OID (2.5.29.31)
const uint8_t X509_CRL_DISTR_POINTS_OID[3] = {0x55, 0x1D, 0x1F};
//Certificate Policies OID (2.5.29.32)
const uint8_t X509_CERTIFICATE_POLICIES_OID[3] = {0x55, 0x1D, 0x20};
//Policy Mappings OID (2.5.29.33)
const uint8_t X509_POLICY_MAPPINGS_OID[3] = {0x55, 0x1D, 0x21};
//Authority Key Identifier OID (2.5.29.35)
const uint8_t X509_AUTHORITY_KEY_ID_OID[3] = {0x55, 0x1D, 0x23};
//Policy Constraints OID (2.5.29.36)
const uint8_t X509_POLICY_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x24};
//Extended Key Usage OID (2.5.29.37)
const uint8_t X509_EXTENDED_KEY_USAGE_OID[3] = {0x55, 0x1D, 0x25};
//Freshest CRL OID (2.5.29.46)
const uint8_t X509_FRESHEST_CRL_OID[3] = {0x55, 0x1D, 0x2E};
//Inhibit Any-Policy OID (2.5.29.54)
const uint8_t X509_INHIBIT_ANY_POLICY_OID[3] = {0x55, 0x1D, 0x36};


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
   memset(certInfo, 0, sizeof(X509CertificateInfo));

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
   error = x509ParseSignatureAlgo(data, length, &totalLength, certInfo);
   //Any error to report?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //Point to the next field
   data += totalLength;
   length -= totalLength;

   //Parse SignatureValue structure
   error = x509ParseSignatureValue(data, length, &totalLength, certInfo);
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

   //The ASN.1 DER encoded tbsCertificate is used as the input to the signature function
   certInfo->tbsCertificate = data;
   certInfo->tbsCertificateLen = tag.totalLength;

   //Point to the very first field of the TBSCertificate
   data = tag.value;
   length = tag.length;

   //Parse Version field
   error = x509ParseVersion(data, length, &n, certInfo);
   //Failed to parse Version field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read SerialNumber field
   error = x509ParseSerialNumber(data, length, &n, certInfo);
   //Failed to parse SerialNumber field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read Signature field
   error = x509ParseSignature(data, length, &n, certInfo);
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
   error = x509ParseValidity(data, length, &n, certInfo);
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
   //Failed to parse Version field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read IssuerUniqueID field (optional)
   error = x509ParseIssuerUniqueId(data, length, &n, certInfo);
   //Failed to parse Version field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read SubjectUniqueID field (optional)
   error = x509ParseSubjectUniqueId(data, length, &n, certInfo);
   //Failed to parse Version field?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Read SubjectUniqueID field (optional)
   error = x509ParseExtensions(data, length, &n, certInfo);
   //Failed to parse Version field?
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
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
      //Assume X.509v1 format
      certInfo->version = X509_VERSION_1;
      //Skip the current field
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Read the inner tag
   error = asn1ReadTag(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Check length field
   if(tag.length != 1)
      return ERROR_INVALID_LENGTH;
   //Check version field
   if(tag.value[0] > X509_VERSION_3)
      return ERROR_INVALID_VERSION;

   //Save certificate version
   certInfo->version = tag.value[0];
   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse SerialNumber field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSerialNumber(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
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

   //Get the signature value
   certInfo->serialNumber = tag.value;
   certInfo->serialNumberLen = tag.length;

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Parse Signature field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSignature(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
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
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OBJECT_IDENTIFIER);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Get the signature algorithm identifier
   certInfo->signatureAlgo = tag.value;
   certInfo->signatureAlgoLen = tag.length;

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
   Asn1Tag tag;
   Asn1Tag attrType;
   Asn1Tag attrValue;

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
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET);
      //The tag does not match the criteria?
      if(error)
         return error;

      //Point to the next attribute
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the inner tag
      error = asn1ReadTag(tag.value, tag.length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
      //The tag does not match the criteria?
      if(error)
         return error;

      //Read attribute type
      error = asn1ReadTag(tag.value, tag.length, &attrType);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&attrType, FALSE,
         ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OBJECT_IDENTIFIER);
      //The tag does not match the criteria?
      if(error)
         return error;

      //Read attribute value
      error = asn1ReadTag(tag.value + attrType.totalLength,
         tag.length - attrType.totalLength, &attrValue);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Check the length of the OID
      if(attrType.length == 3)
      {
         //Common Name attribute found?
         if(!memcmp(attrType.value, X509_COMMON_NAME_OID, 3))
         {
            name->commonName = (const char_t *) attrValue.value;
            name->commonNameLen = attrValue.length;
         }
         //Surname attribute found?
         else if(!memcmp(attrType.value, X509_SURNAME_OID, 3))
         {
            name->surname = (const char_t *) attrValue.value;
            name->surnameLen = attrValue.length;
         }
         //Serial Number attribute found?
         else if(!memcmp(attrType.value, X509_SERIAL_NUMBER_OID, 3))
         {
            name->serialNumber = (const char_t *) attrValue.value;
            name->serialNumberLen = attrValue.length;
         }
         //Country Name attribute found?
         else if(!memcmp(attrType.value, X509_COUNTRY_NAME_OID, 3))
         {
            name->countryName = (const char_t *) attrValue.value;
            name->countryNameLen = attrValue.length;
         }
         //Locality Name attribute found?
         else if(!memcmp(attrType.value, X509_LOCALITY_NAME_OID, 3))
         {
            name->localityName = (const char_t *) attrValue.value;
            name->localityNameLen = attrValue.length;
         }
         //State Or Province Name attribute found?
         else if(!memcmp(attrType.value, X509_STATE_OR_PROVINCE_NAME_OID, 3))
         {
            name->stateOrProvinceName = (const char_t *) attrValue.value;
            name->stateOrProvinceNameLen = attrValue.length;
         }
         //Organization Name attribute found?
         else if(!memcmp(attrType.value, X509_ORGANIZATION_NAME_OID, 3))
         {
            name->organizationName = (const char_t *) attrValue.value;
            name->organizationNameLen = attrValue.length;
         }
         //Organizational Unit Name attribute found?
         else if(!memcmp(attrType.value, X509_ORGANIZATIONAL_UNIT_NAME_OID, 3))
         {
            name->organizationalUnitName = (const char_t *) attrValue.value;
            name->organizationalUnitNameLen = attrValue.length;
         }
         //Title attribute found?
         else if(!memcmp(attrType.value, X509_TITLE_OID, 3))
         {
            name->title = (const char_t *) attrValue.value;
            name->titleLen = attrValue.length;
         }
         //Name attribute found?
         else if(!memcmp(attrType.value, X509_NAME_OID, 3))
         {
            name->name = (const char_t *) attrValue.value;
            name->nameLen = attrValue.length;
         }
         //Given Name attribute found?
         else if(!memcmp(attrType.value, X509_GIVEN_NAME_OID, 3))
         {
            name->givenName = (const char_t *) attrValue.value;
            name->givenNameLen = attrValue.length;
         }
         //Initials attribute OID (2.5.4.43)
         else if(!memcmp(attrType.value, X509_INITIALS_OID, 3))
         {
            name->initials = (const char_t *) attrValue.value;
            name->initialsLen = attrValue.length;
         }
         //Generation Qualifier attribute found?
         else if(!memcmp(attrType.value, X509_GENERATION_QUALIFIER_OID, 3))
         {
            name->generationQualifier = (const char_t *) attrValue.value;
            name->generationQualifierLen = attrValue.length;
         }
         //DN Qualifier attribute found?
         else if(!memcmp(attrType.value, X509_DN_QUALIFIER_OID, 3))
         {
            name->dnQualifier = (const char_t *) attrValue.value;
            name->dnQualifierLen = attrValue.length;
         }
         //Pseudonym attribute found?
         else if(!memcmp(attrType.value, X509_PSEUDONYM_OID, 3))
         {
            name->pseudonym = (const char_t *) attrValue.value;
            name->pseudonymLen = attrValue.length;
         }
      }
   }

   //Name field successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse Validity field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseValidity(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing Validity...\r\n");

   //Read current ASN.1 tag
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

   //NotBefore field may be encoded as UTCTime or GeneralizedTime
   error = x509ParseTime(data, length, &n, &certInfo->validity.notBefore);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //NotAfter field may be encoded as UTCTime or GeneralizedTime
   error = x509ParseTime(data, length, &n, &certInfo->validity.notAfter);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Validity field successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse UTCTime or GeneralizedTime structure
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
      if(tag.length < 12)
         return ERROR_INVALID_SYNTAX;

      //The UTCTime uses a 2-digit representation of the year
      error = x509ParseInt(tag.value, 2, &value);
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
      if(tag.length < 14)
         return ERROR_INVALID_SYNTAX;

      //The GeneralizedTime uses a 4-digit representation of the year
      error = x509ParseInt(tag.value, 4, &value);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      data = tag.value + 4;
   }
   else
   {
      //The tag does not contain a valid date
      return ERROR_FAILURE;
   }

   //Month
   error = x509ParseInt(data, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->month = value;

   //Day
   error = x509ParseInt(data + 2, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->day = value;

   //Hours
   error = x509ParseInt(data + 4, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->hours = value;

   //Minutes
   error = x509ParseInt(data + 6, 2, &value);
   //Any error to report?
   if(error)
      return error;

   //Save the resulting value
   dateTime->minutes = value;

   //Seconds
   error = x509ParseInt(data + 8, 2, &value);
   //Any error to report?
   if(error)
      return error;

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

   //The bit string shall contain an initial octet which encodes
   //the number of unused bits in the final subsequent octet
   if(tag.length < 1 || tag.value[0] != 0x00)
      return ERROR_FAILURE;

#if (RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!oidComp(certInfo->subjectPublicKeyInfo.oid, certInfo->subjectPublicKeyInfo.oidLen,
      RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //Read RSAPublicKey structure
      error = x509ParseRsaPublicKey(tag.value + 1, tag.length - 1, certInfo);
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!oidComp(certInfo->subjectPublicKeyInfo.oid, certInfo->subjectPublicKeyInfo.oidLen,
      DSA_OID, sizeof(DSA_OID)))
   {
      //Read DSAPublicKey structure
      error = x509ParseDsaPublicKey(tag.value + 1, tag.length - 1, certInfo);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
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
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OBJECT_IDENTIFIER);
   //The tag does not match the criteria?
   if(error)
      return error;

   //Save the algorithm identifier
   certInfo->subjectPublicKeyInfo.oid = tag.value;
   certInfo->subjectPublicKeyInfo.oidLen = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

#if (RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!asn1CheckOid(&tag, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //RSA does not require any additional parameters
      error = NO_ERROR;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!asn1CheckOid(&tag, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DsaParameters structure
      error = x509ParseDsaParameters(data, length, certInfo);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
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
#if (RSA_SUPPORT == ENABLED)
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
#if (DSA_SUPPORT == ENABLED)
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
#if (DSA_SUPPORT == ENABLED)
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
#if (EC_SUPPORT == ENABLED)
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
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OBJECT_IDENTIFIER);
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
#if (EC_SUPPORT == ENABLED)
   //Debug message
   TRACE_DEBUG("      Parsing ECPublicKey...\r\n");

   //Make sure the EC public key is valid
   if(!length)
      return ERROR_BAD_CERTIFICATE;

   //Save the EC public value
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
      error = asn1CheckTag(&oidTag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OBJECT_IDENTIFIER);
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

         //Each extension in a certificate is designated as either
         //critical or non-critical
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
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING);
      //The tag does not match the criteria?
      if(error)
         return error;

      //The current extension matches the BasicConstraints OID?
      if(!oidComp(oidTag.value, oidTag.length, X509_BASIC_CONSTRAINTS_OID, 3))
      {
         //Parse BasicConstraints extension
         error = x509ParseBasicConstraints(tag.value, tag.length, certInfo);
         //Any error to report?
         if(error)
            return error;
      }
      //The current extension matches the KeyUsage OID?
      else if(!oidComp(oidTag.value, oidTag.length, X509_KEY_USAGE_OID, 3))
      {
         //Parse KeyUsage extension
      }
      //The current extension matches the ExtendedKeyUsage OID?
      else if(!oidComp(oidTag.value, oidTag.length, X509_EXTENDED_KEY_USAGE_OID, 3))
      {
         //Parse ExtendedKeyUsage extension
      }
      //The current extension is marked as critical?
      else if(critical)
      {
         //A certificate-using system must reject the certificate if it encounters
         //a critical extension it does not recognize or a critical extension that
         //contains information that it cannot process
         return ERROR_UNSUPPORTED_EXTENSION;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse BasicConstraints structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseBasicConstraints(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo)
{
   error_t error;
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

   //The cA boolean is optional...
   if(length > 0)
   {
      //The cA boolean indicates whether the certified public key
      //may be used to verify certificate signatures
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BOOLEAN);

      //The cA field is present?
      if(!error)
      {
         //The tag should be 1-byte long
         if(tag.length != 1)
            return ERROR_INVALID_LENGTH;

         //Get boolean value
         certInfo->basicConstraints.ca = tag.value ? TRUE : FALSE;

         //Point to the next item
         data += tag.totalLength;
         length -= tag.totalLength;
      }
   }

   //The pathLenConstraint field is optional...
   if(length > 0)
   {
      //The pathLenConstraint field gives the maximum number of non-self-issued
      //intermediate certificates that may follow this certificate in a valid
      //certification path
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         return error;

      //The pathLenConstraint field is not supported
      certInfo->basicConstraints.pathLenConstraint = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SignatureAlgorithm structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSignatureAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
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

   //This field must contain the same algorithm identifier
   //as the signature field in the TBSCertificate sequence
   error = asn1CheckOid(&tag, certInfo->signatureAlgo, certInfo->signatureAlgoLen);
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
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSignatureValue(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo)
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
   certInfo->signatureValue = tag.value + 1;
   certInfo->signatureValueLen = tag.length - 1;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Convert string to integer
 * @param[in] data String containing the representation of an integral number
 * @param[in] length Length of the string
 * @param[out] value On success, the function returns the converted integral number
 * @return Error code
 **/

error_t x509ParseInt(const uint8_t *data, size_t length, uint_t *value)
{
   //Initialize integer value
   *value = 0;

   //Parse the string
   while(length > 0)
   {
      //Check whether the character is decimal digit
      if(!isdigit(*data))
         return ERROR_FAILURE;

      //Convert the string to integer
      *value = *value * 10 + (*data - '0');

      //Next character
      data++;
      length--;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read a RSA public key
 * @param[in] certInfo X.509 certificate
 * @param[out] key RSA public key
 * @return Error code
 **/

error_t x509ReadRsaPublicKey(const X509CertificateInfo *certInfo, RsaPublicKey *key)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;

   //The certificate shall contain a valid RSA public key
   if(!certInfo->subjectPublicKeyInfo.rsaPublicKey.n ||
      !certInfo->subjectPublicKeyInfo.rsaPublicKey.e)
   {
      //Report an error
      return ERROR_INVALID_KEY;
   }

   //Convert the modulus to a big number
   error = mpiReadRaw(&key->n, certInfo->subjectPublicKeyInfo.rsaPublicKey.n,
      certInfo->subjectPublicKeyInfo.rsaPublicKey.nLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the public exponent to a big number
   error = mpiReadRaw(&key->e, certInfo->subjectPublicKeyInfo.rsaPublicKey.e,
      certInfo->subjectPublicKeyInfo.rsaPublicKey.eLen);
   //Convertion failed?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("RSA public key:\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Read a DSA public key
 * @param[in] certInfo X.509 certificate
 * @param[out] key DSA public key
 * @return Error code
 **/

error_t x509ReadDsaPublicKey(const X509CertificateInfo *certInfo, DsaPublicKey *key)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;

   //The certificate shall contain a valid DSA public key
   if(!certInfo->subjectPublicKeyInfo.dsaParams.p ||
      !certInfo->subjectPublicKeyInfo.dsaParams.q ||
      !certInfo->subjectPublicKeyInfo.dsaParams.g ||
      !certInfo->subjectPublicKeyInfo.dsaPublicKey.y)
   {
      //Report an error
      return ERROR_INVALID_KEY;
   }

   //Convert the parameter p to a big number
   error = mpiReadRaw(&key->p, certInfo->subjectPublicKeyInfo.dsaParams.p,
      certInfo->subjectPublicKeyInfo.dsaParams.pLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the parameter q to a big number
   error = mpiReadRaw(&key->q, certInfo->subjectPublicKeyInfo.dsaParams.q,
      certInfo->subjectPublicKeyInfo.dsaParams.qLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the parameter g to a big number
   error = mpiReadRaw(&key->g, certInfo->subjectPublicKeyInfo.dsaParams.g,
      certInfo->subjectPublicKeyInfo.dsaParams.gLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the public value to a big number
   error = mpiReadRaw(&key->y, certInfo->subjectPublicKeyInfo.dsaPublicKey.y,
      certInfo->subjectPublicKeyInfo.dsaPublicKey.yLen);
   //Convertion failed?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("DSA public key:\r\n");
   TRACE_DEBUG("  Parameter p:\r\n");
   TRACE_DEBUG_MPI("    ", &key->p);
   TRACE_DEBUG("  Parameter q:\r\n");
   TRACE_DEBUG_MPI("    ", &key->q);
   TRACE_DEBUG("  Parameter g:\r\n");
   TRACE_DEBUG_MPI("    ", &key->g);
   TRACE_DEBUG("  Public value y:\r\n");
   TRACE_DEBUG_MPI("    ", &key->y);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief X.509 certificate validation
 * @param[in] certInfo X.509 certificate to be verified
 * @param[in] issuerCertInfo Issuer certificate
 * @return Error code
 **/

error_t x509ValidateCertificate(const X509CertificateInfo *certInfo,
   const X509CertificateInfo *issuerCertInfo)
{
   error_t error;
   time_t currentTime;
   time_t notBefore;
   time_t notAfter;
   const HashAlgo *hashAlgo;
   HashContext *hashContext;

   //Use RSA, DSA or ECDSA signature algorithm?
#if (RSA_SUPPORT == ENABLED)
   bool_t rsaSignAlgo = FALSE;
#endif
#if (DSA_SUPPORT == ENABLED)
   bool_t dsaSignAlgo = FALSE;
#endif
#if (ECDSA_SUPPORT == ENABLED)
   bool_t ecdsaSignAlgo = FALSE;
#endif

   //Retrieve current time
   currentTime = getCurrentUnixTime();

   //Any real-time clock implemented?
   if(currentTime != 0)
   {
      //Convert NotBefore and NotAfter to Unix timestamps
      notBefore = convertDateToUnixTime(&certInfo->validity.notBefore);
      notAfter = convertDateToUnixTime(&certInfo->validity.notAfter);

      //Check the certificate validity period
      if(currentTime < notBefore || currentTime > notAfter)
         return ERROR_CERTIFICATE_EXPIRED;
   }

   //Make sure that the subject and issuer names chain correctly
   if(certInfo->issuer.rawDataLen != issuerCertInfo->subject.rawDataLen)
      return ERROR_BAD_CERTIFICATE;
   if(memcmp(certInfo->issuer.rawData, issuerCertInfo->subject.rawData, certInfo->issuer.rawDataLen))
      return ERROR_BAD_CERTIFICATE;

   //Ensure that the issuer certificate is a CA certificate
   if(issuerCertInfo->version >= X509_VERSION_3 && !issuerCertInfo->basicConstraints.ca)
      return ERROR_BAD_CERTIFICATE;

   //Retrieve the signature algorithm that has been used to sign the certificate
#if (RSA_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      MD5_WITH_RSA_ENCRYPTION_OID, sizeof(MD5_WITH_RSA_ENCRYPTION_OID)))
   {
      //MD5 with RSA signature algorithm
      rsaSignAlgo = TRUE;
      hashAlgo = MD5_HASH_ALGO;
   }
   else
#endif
#if (RSA_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      SHA1_WITH_RSA_ENCRYPTION_OID, sizeof(SHA1_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-1 with RSA signature algorithm
      rsaSignAlgo = TRUE;
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (RSA_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      SHA256_WITH_RSA_ENCRYPTION_OID, sizeof(SHA256_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-256 with RSA signature algorithm
      rsaSignAlgo = TRUE;
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (RSA_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      SHA384_WITH_RSA_ENCRYPTION_OID, sizeof(SHA384_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-384 with RSA signature algorithm
      rsaSignAlgo = TRUE;
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (RSA_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      SHA512_WITH_RSA_ENCRYPTION_OID, sizeof(SHA512_WITH_RSA_ENCRYPTION_OID)))
   {
      //SHA-512 with RSA signature algorithm
      rsaSignAlgo = TRUE;
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      DSA_WITH_SHA1_OID, sizeof(DSA_WITH_SHA1_OID)))
   {
      //DSA with SHA-1 signature algorithm
      dsaSignAlgo = TRUE;
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      DSA_WITH_SHA224_OID, sizeof(DSA_WITH_SHA224_OID)))
   {
      //DSA with SHA-224 signature algorithm
      dsaSignAlgo = TRUE;
      hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      DSA_WITH_SHA256_OID, sizeof(DSA_WITH_SHA256_OID)))
   {
      //DSA with SHA-256 signature algorithm
      dsaSignAlgo = TRUE;
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      ECDSA_WITH_SHA1_OID, sizeof(ECDSA_WITH_SHA1_OID)))
   {
      //ECDSA with SHA-1 signature algorithm
      ecdsaSignAlgo = TRUE;
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      ECDSA_WITH_SHA224_OID, sizeof(ECDSA_WITH_SHA224_OID)))
   {
      //ECDSA with SHA-224 signature algorithm
      ecdsaSignAlgo = TRUE;
      hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      ECDSA_WITH_SHA256_OID, sizeof(ECDSA_WITH_SHA256_OID)))
   {
      //ECDSA with SHA-256 signature algorithm
      ecdsaSignAlgo = TRUE;
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      ECDSA_WITH_SHA384_OID, sizeof(ECDSA_WITH_SHA384_OID)))
   {
      //ECDSA with SHA-384 signature algorithm
      ecdsaSignAlgo = TRUE;
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   if(!oidComp(certInfo->signatureAlgo, certInfo->signatureAlgoLen,
      ECDSA_WITH_SHA512_OID, sizeof(ECDSA_WITH_SHA512_OID)))
   {
      //ECDSA with SHA-512 signature algorithm
      ecdsaSignAlgo = TRUE;
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   {
      //The specified signature algorithm is not supported
      return ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hashAlgo->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Digest the TBSCertificate structure using the specified hash algorithm
   hashAlgo->init(hashContext);
   hashAlgo->update(hashContext, certInfo->tbsCertificate, certInfo->tbsCertificateLen);
   hashAlgo->final(hashContext, NULL);

   //Check signature algorithm
#if (RSA_SUPPORT == ENABLED)
   if(rsaSignAlgo)
   {
      RsaPublicKey publicKey;

      //Initialize RSA public key
      rsaInitPublicKey(&publicKey);

      //Get the RSA public key
      error = x509ReadRsaPublicKey(issuerCertInfo, &publicKey);

      //Check status code
      if(!error)
      {
         //Verify RSA signature
         error = rsassaPkcs1v15Verify(&publicKey, hashAlgo, hashContext->digest,
            certInfo->signatureValue, certInfo->signatureValueLen);
      }

      //Release previously allocated resources
      rsaFreePublicKey(&publicKey);
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   if(dsaSignAlgo)
   {
      DsaPublicKey publicKey;
      DsaSignature signature;

      //Initialize DSA public key
      dsaInitPublicKey(&publicKey);
      //Initialize DSA signature
      dsaInitSignature(&signature);

      //Get the DSA public key
      error = x509ReadDsaPublicKey(issuerCertInfo, &publicKey);

      //Check status code
      if(!error)
      {
         //Read the ASN.1 encoded signature
         error = dsaReadSignature(certInfo->signatureValue,
            certInfo->signatureValueLen, &signature);
      }

      //Check status code
      if(!error)
      {
         //Verify DSA signature
         error = dsaVerifySignature(&publicKey, hashContext->digest,
            hashAlgo->digestSize, &signature);
      }

      //Release previously allocated resources
      dsaFreePublicKey(&publicKey);
      dsaFreeSignature(&signature);
   }
   else
#endif
#if (ECDSA_SUPPORT == ENABLED)
   if(ecdsaSignAlgo)
   {
      const EcCurveInfo *curveInfo;
      EcDomainParameters params;
      EcPoint publicKey;
      EcdsaSignature signature;

      //Initialize EC domain parameters
      ecInitDomainParameters(&params);
      //Initialize ECDSA public key
      ecInit(&publicKey);
      //Initialize ECDSA signature
      ecdsaInitSignature(&signature);

      //Retrieve EC domain parameters
      curveInfo = ecGetCurveInfo(issuerCertInfo->subjectPublicKeyInfo.ecParams.namedCurve,
         issuerCertInfo->subjectPublicKeyInfo.ecParams.namedCurveLen);

      //Make sure the specified elliptic curve is supported
      error = (curveInfo == NULL) ? ERROR_BAD_CERTIFICATE : NO_ERROR;

      //Check status code
      if(!error)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&params, curveInfo);
      }

      //Check status code
      if(!error)
      {
         //Retrieve the EC public key
         error = ecImport(&params, &publicKey, issuerCertInfo->subjectPublicKeyInfo.ecPublicKey.q,
            issuerCertInfo->subjectPublicKeyInfo.ecPublicKey.qLen);
      }

      //Check status code
      if(!error)
      {
         //Read the ASN.1 encoded signature
         error = ecdsaReadSignature(certInfo->signatureValue,
            certInfo->signatureValueLen, &signature);
      }

      //Check status code
      if(!error)
      {
         //Verify ECDSA signature
         error = ecdsaVerifySignature(&params, &publicKey,
            hashContext->digest, hashAlgo->digestSize, &signature);
      }

      //Release previously allocated resources
      ecFreeDomainParameters(&params);
      ecFree(&publicKey);
      ecdsaFreeSignature(&signature);
   }
   else
#endif
   {
      //The signature algorithm is not supported...
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Release hash algorithm context
   cryptoFreeMem(hashContext);
   //Return status code
   return error;
}

#endif
