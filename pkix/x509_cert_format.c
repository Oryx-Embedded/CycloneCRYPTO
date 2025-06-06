/**
 * @file x509_cert_format.c
 * @brief X.509 certificate formatting
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
#include "pkix/x509_cert_format.h"
#include "pkix/x509_cert_ext_format.h"
#include "pkix/x509_key_format.h"
#include "pkix/x509_sign_format.h"
#include "encoding/asn1.h"
#include "hash/sha1.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Format TBSCertificate structure
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] serialNumber Serial number
 * @param[in] signatureAlgo Signature algorithm
 * @param[in] issuer Issuer's name
 * @param[in] validity Validity period
 * @param[in] subject Subject's name
 * @param[in] subjectPublicKeyInfo Subject's public key information
 * @param[in] publicKey Subject's public key
 * @param[in] extensions X.509 certificates extensions
 * @param[in] authKeyId AuthorityKeyIdentifier extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatTbsCertificate(const PrngAlgo *prngAlgo, void *prngContext,
   const X509SerialNumber *serialNumber, const X509SignAlgoId *signatureAlgo,
   const X509Name *issuer, const X509Validity *validity, const X509Name *subject,
   const X509SubjectPublicKeyInfo *subjectPublicKeyInfo, const void *publicKey,
   const X509Extensions *extensions, const X509AuthKeyId *authKeyId,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509SubjectKeyId subjectKeyId;
   uint8_t digest[SHA1_DIGEST_SIZE];

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Format Version field
   error = x509FormatVersion(X509_VERSION_3, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format SerialNumber field
   error = x509FormatSerialNumber(prngAlgo, prngContext, serialNumber, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format Signature field
   error = x509FormatSignatureAlgo(signatureAlgo, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format Issuer field
   error = x509FormatName(issuer, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format Validity field
   error = x509FormatValidity(validity, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format Subject field
   error = x509FormatName(subject, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format SubjectPublicKeyInfo field
   error = x509FormatSubjectPublicKeyInfo(subjectPublicKeyInfo, publicKey,
      digest, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The SubjectKeyIdentifier extension provides a means of identifying
   //certificates that contain a particular public key
   subjectKeyId.critical = FALSE;
   subjectKeyId.value = digest;
   subjectKeyId.length = SHA1_DIGEST_SIZE;

   //The Extensions field must only appear if the version is 3
   error = x509FormatExtensions(extensions, &subjectKeyId, authKeyId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The TBSCertificate structure is encapsulated within a sequence
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
 * @brief Format Version field
 * @param[in] version Version number
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatVersion(X509Version version, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Encode the version number
   error = asn1WriteInt32(version, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Explicit tagging shall be used to encode version
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
   tag.objType = 0;
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
 * @brief Format SerialNumber field
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] serialNumber Pointer to the serial number (optional parameter)
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatSerialNumber(const PrngAlgo *prngAlgo, void *prngContext,
   const X509SerialNumber *serialNumber, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Initialize status code
   error = NO_ERROR;

   //Valid serial number?
   if(serialNumber != NULL)
   {
      //The serial number is a unique integer assigned by the CA to each
      //certificate
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_INTEGER;
      tag.length = serialNumber->length;
      tag.value = serialNumber->value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
   }
   else
   {
      //If the output parameter is NULL, then the function calculates the
      //length of the octet string without copying any data
      if(output != NULL)
      {
         //Conforming CAs must not use serial number values longer than 20
         //octets
         error = prngAlgo->generate(prngContext, output,
            X509_SERIAL_NUMBER_SIZE);

         //Check status code
         if(!error)
         {
            //CAs must force the serial number to be a non-negative integer
            output[0] = (output[0] & 0x3F) | 0x40;
         }
      }

      //Check status code
      if(!error)
      {
         //The serial number is a unique integer assigned by the CA to each
         //certificate
         tag.constructed = FALSE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_INTEGER;
         tag.length = X509_SERIAL_NUMBER_SIZE;

         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, output, &n);
      }
   }

   //Check status code
   if(!error)
   {
      //Total number of bytes that have been written
      *written = tag.totalLength;
   }

   //Return status code
   return error;
}


/**
 * @brief Format Name structure
 * @param[in] name Information about the name to be encoded
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatName(const X509Name *name, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509NameAttribute nameAttribute;

   //Initialize status code
   error = NO_ERROR;

   //Raw ASN.1 sequence?
   if(name->raw.value != NULL && name->raw.length > 0)
   {
      //Copy raw ASN.1 sequence
      if(output != NULL)
      {
         osMemcpy(output, name->raw.value, name->raw.length);
      }

      //Total number of bytes that have been written
      *written = name->raw.length;
   }
   else
   {
      //Point to the buffer where to write the Name structure
      p = output;
      //Length of the Name structure
      length = 0;

      //Valid Country Name attribute?
      if(name->countryName.value != NULL && name->countryName.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = X509_COUNTRY_NAME_OID;
         nameAttribute.oid.length = sizeof(X509_COUNTRY_NAME_OID);
         nameAttribute.type = ASN1_TYPE_PRINTABLE_STRING;
         nameAttribute.data.value = name->countryName.value;
         nameAttribute.data.length = name->countryName.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Valid State Or Province Name attribute?
      if(name->stateOrProvinceName.value != NULL && name->stateOrProvinceName.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = X509_STATE_OR_PROVINCE_NAME_OID;
         nameAttribute.oid.length = sizeof(X509_STATE_OR_PROVINCE_NAME_OID);
         nameAttribute.type = ASN1_TYPE_UTF8_STRING;
         nameAttribute.data.value = name->stateOrProvinceName.value;
         nameAttribute.data.length = name->stateOrProvinceName.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Valid Locality Name attribute?
      if(name->localityName.value != NULL && name->localityName.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = X509_LOCALITY_NAME_OID;
         nameAttribute.oid.length = sizeof(X509_LOCALITY_NAME_OID);
         nameAttribute.type = ASN1_TYPE_UTF8_STRING;
         nameAttribute.data.value = name->localityName.value;
         nameAttribute.data.length = name->localityName.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Valid Organization Name attribute?
      if(name->organizationName.value != NULL && name->organizationName.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = X509_ORGANIZATION_NAME_OID;
         nameAttribute.oid.length = sizeof(X509_ORGANIZATION_NAME_OID);
         nameAttribute.type = ASN1_TYPE_UTF8_STRING;
         nameAttribute.data.value = name->organizationName.value;
         nameAttribute.data.length = name->organizationName.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Valid Organizational Unit Name attribute?
      if(name->organizationalUnitName.value != NULL && name->organizationalUnitName.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = X509_ORGANIZATIONAL_UNIT_NAME_OID;
         nameAttribute.oid.length = sizeof(X509_ORGANIZATIONAL_UNIT_NAME_OID);
         nameAttribute.type = ASN1_TYPE_UTF8_STRING;
         nameAttribute.data.value = name->organizationalUnitName.value;
         nameAttribute.data.length = name->organizationalUnitName.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Valid Common Name attribute?
      if(name->commonName.value != NULL && name->commonName.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = X509_COMMON_NAME_OID;
         nameAttribute.oid.length = sizeof(X509_COMMON_NAME_OID);
         nameAttribute.type = ASN1_TYPE_UTF8_STRING;
         nameAttribute.data.value = name->commonName.value;
         nameAttribute.data.length = name->commonName.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Valid E-mail Address attribute?
      if(name->emailAddress.value != NULL && name->emailAddress.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = PKCS9_EMAIL_ADDR_OID;
         nameAttribute.oid.length = sizeof(PKCS9_EMAIL_ADDR_OID);
         nameAttribute.type = ASN1_TYPE_IA5_STRING;
         nameAttribute.data.value = name->emailAddress.value;
         nameAttribute.data.length = name->emailAddress.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Valid Serial Number attribute?
      if(name->serialNumber.value != NULL && name->serialNumber.length > 0)
      {
         //Set attribute type and value
         nameAttribute.oid.value = X509_SERIAL_NUMBER_OID;
         nameAttribute.oid.length = sizeof(X509_SERIAL_NUMBER_OID);
         nameAttribute.type = ASN1_TYPE_PRINTABLE_STRING;
         nameAttribute.data.value = name->serialNumber.value;
         nameAttribute.data.length = name->serialNumber.length;

         //Encode the attribute to ASN.1 format
         error = x509FormatNameAttribute(&nameAttribute, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //The Name structure is encapsulated within a sequence
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
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format name attribute
 * @param[in] nameAttribute Name attribute
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatNameAttribute(const X509NameAttribute *nameAttribute,
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

   //Format AttributeType field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = nameAttribute->oid.length;
   tag.value = nameAttribute->oid.value;

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
   tag.objType = nameAttribute->type;
   tag.length = nameAttribute->data.length;
   tag.value = (uint8_t *) nameAttribute->data.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The attribute type and value are encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The sequence is encapsulated within a set
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SET;
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
 * @brief Format Validity structure
 * @param[in] validity Validity period
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatValidity(const X509Validity *validity, uint8_t *output,
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

   //The NotBefore field may be encoded as UTCTime or GeneralizedTime
   error = x509FormatTime(&validity->notBefore, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The NotAfter field may be encoded as UTCTime or GeneralizedTime
   error = x509FormatTime(&validity->notAfter, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The Validity structure is encapsulated within a sequence
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
 * @brief Format UTCTime or GeneralizedTime field
 * @param[in] dateTime Date to be encoded
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatTime(const DateTime *dateTime, uint8_t *output,
   size_t *written)
{
   error_t error;
   uint_t type;
   size_t n;
   Asn1Tag tag;
   char_t buffer[24];

   //UTCTime is limited to the period from 1950 to 2049
   if(dateTime->year >= 1950 && dateTime->year <= 2049)
   {
      //Use UTCTime format
      type = ASN1_TYPE_UTC_TIME;
   }
   else
   {
      //Use GeneralizedTime format
      type = ASN1_TYPE_GENERALIZED_TIME;
   }

   //Format UTCTime or GeneralizedTime string
   error = x509FormatTimeString(dateTime, type, buffer);
   //Any error to report?
   if(error)
      return error;

   //The date may be encoded as UTCTime or GeneralizedTime
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = type;
   tag.length = osStrlen(buffer);
   tag.value = (uint8_t *) buffer;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format UTCTime or GeneralizedTime string
 * @param[in] dateTime Date to be encoded
 * @param[in] type Time format (UTCTime or GeneralizedTime)
 * @param[out] output Buffer where to format the string
 * @return Error code
 **/

error_t x509FormatTimeString(const DateTime *dateTime, uint_t type,
   char_t *output)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //The date may be encoded as UTCTime or GeneralizedTime
   if(type == ASN1_TYPE_UTC_TIME)
   {
      //UTCTime is limited to the period from 1950 to 2049
      if(dateTime->year >= 1950 && dateTime->year <= 2049)
      {
         //The UTCTime uses a 2-digit representation of the year. If YY is
         //greater than or equal to 50, the year shall be interpreted as 19YY.
         //If YY is less than 50, the year shall be interpreted as 20YY
         osSprintf(output, "%02" PRIu16 "%02" PRIu8 "%02" PRIu8
            "%02" PRIu8 "%02" PRIu8 "%02" PRIu8 "Z",
            dateTime->year % 100, dateTime->month, dateTime->day,
            dateTime->hours, dateTime->minutes, dateTime->seconds);
      }
      else
      {
         //Report an error
         error = ERROR_OUT_OF_RANGE;
      }
   }
   else if(type == ASN1_TYPE_GENERALIZED_TIME)
   {
      //The GeneralizedTime uses a 4-digit representation of the year
      osSprintf(output, "%04" PRIu16 "%02" PRIu8 "%02" PRIu8
         "%02" PRIu8 "%02" PRIu8 "%02" PRIu8 "Z",
         dateTime->year, dateTime->month, dateTime->day,
         dateTime->hours, dateTime->minutes, dateTime->seconds);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
}

#endif
