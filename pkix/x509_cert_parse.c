/**
 * @file x509_cert_parse.c
 * @brief X.509 certificate parsing
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.3.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_ext_parse.h"
#include "pkix/x509_key_parse.h"
#include "pkix/x509_sign_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
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
   X509CertInfo *certInfo)
{
   //Parse the certificate
   return x509ParseCertificateEx(data, length, certInfo, FALSE);
}


/**
 * @brief Parse a X.509 certificate
 * @param[in] data Pointer to the X.509 certificate to parse
 * @param[in] length Length of the X.509 certificate
 * @param[out] certInfo Information resulting from the parsing process
 * @param[in] ignoreUnknown Ignore unknown extensions
 * @return Error code
 **/

error_t x509ParseCertificateEx(const uint8_t *data, size_t length,
   X509CertInfo *certInfo, bool_t ignoreUnknown)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Parsing X.509 certificate...\r\n");

   //Check parameters
   if(data == NULL || certInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the certificate information structure
   osMemset(certInfo, 0, sizeof(X509CertInfo));

   //Where pathLenConstraint does not appear, no limit is imposed
   certInfo->tbsCert.extensions.basicConstraints.pathLenConstraint = -1;

   //Read the contents of the certificate
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse TBSCertificate structure
   error = x509ParseTbsCertificate(data, length, &n, &certInfo->tbsCert,
      ignoreUnknown);
   //Any error to report?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SignatureAlgorithm structure
   error = x509ParseSignatureAlgo(data, length, &n, &certInfo->signatureAlgo);
   //Any error to report?
   if(error)
      return ERROR_BAD_CERTIFICATE;

   //This field must contain the same algorithm identifier as the signature
   //field in the TBSCertificate sequence (refer to RFC 5280, section 4.1.1.2)
   if(oidComp(certInfo->signatureAlgo.oid.value,
      certInfo->signatureAlgo.oid.length,
      certInfo->tbsCert.signatureAlgo.oid.value,
      certInfo->tbsCert.signatureAlgo.oid.length))
   {
      //Report an error
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the next field
   data += n;
   length -= n;

   //Parse SignatureValue structure
   error = x509ParseSignatureValue(data, length, &n, &certInfo->signatureValue);
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
 * @param[out] tbsCert Information resulting from the parsing process
 * @param[in] ignoreUnknown Ignore unknown extensions
 * @return Error code
 **/

error_t x509ParseTbsCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertificate *tbsCert, bool_t ignoreUnknown)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing TBSCertificate...\r\n");

   //Read the contents of the TBSCertificate structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The ASN.1 DER-encoded TBSCertificate is used as the input to the
   //signature function
   tbsCert->raw.value = data;
   tbsCert->raw.length = tag.totalLength;

   //Point to the very first field of the TBSCertificate
   data = tag.value;
   length = tag.length;

   //Parse Version field
   error = x509ParseVersion(data, length, &n, &tbsCert->version);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SerialNumber field
   error = x509ParseSerialNumber(data, length, &n, &tbsCert->serialNumber);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Signature field
   error = x509ParseSignatureAlgo(data, length, &n, &tbsCert->signatureAlgo);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Issuer field
   error = x509ParseName(data, length, &n, &tbsCert->issuer);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Validity field
   error = x509ParseValidity(data, length, &n, &tbsCert->validity);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Subject field
   error = x509ParseName(data, length, &n, &tbsCert->subject);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SubjectPublicKeyInfo field
   error = x509ParseSubjectPublicKeyInfo(data, length, &n,
      &tbsCert->subjectPublicKeyInfo);
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
      if(tbsCert->version < X509_VERSION_2)
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
      if(tbsCert->version < X509_VERSION_2)
         return ERROR_INVALID_VERSION;
   }

   //Point to the next field
   data += n;
   length -= n;

   //Parse Extensions field
   error = x509ParseCertExtensions(data, length, &n, &tbsCert->extensions,
      ignoreUnknown);
   //Any parsing error?
   if(error)
      return error;

   //The Extensions field is optional
   if(n > 0)
   {
      //This field must only appear if the version is 3
      if(tbsCert->version < X509_VERSION_3)
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
   serialNumber->value = tag.value;
   serialNumber->length = tag.length;

   //No error to report
   return NO_ERROR;
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
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509NameAttribute nameAttribute;

   //Debug message
   TRACE_DEBUG("    Parsing Name...\r\n");

   //Clear the structure
   osMemset(name, 0, sizeof(X509Name));

   //Read the contents of the Name structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   name->raw.value = data;
   name->raw.length = tag.totalLength;

   //The Name describes a hierarchical name composed of attributes
   data = tag.value;
   length = tag.length;

   //Number of domain components
   i = 0;

   //Loop through all the attributes
   while(length > 0)
   {
      //Read current attribute
      error = x509ParseNameAttribute(data, length, &n, &nameAttribute);
      //Any error to report?
      if(error)
         return error;

      //Check attribute type
      if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_COMMON_NAME_OID, sizeof(X509_COMMON_NAME_OID)))
      {
         //Save Common Name attribute
         name->commonName.value = nameAttribute.data.value;
         name->commonName.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_SURNAME_OID, sizeof(X509_SURNAME_OID)))
      {
         //Save Surname attribute
         name->surname.value = nameAttribute.data.value;
         name->surname.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_SERIAL_NUMBER_OID, sizeof(X509_SERIAL_NUMBER_OID)))
      {
         //Save Serial Number attribute
         name->serialNumber.value = nameAttribute.data.value;
         name->serialNumber.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_COUNTRY_NAME_OID, sizeof(X509_COUNTRY_NAME_OID)))
      {
         //Save Country Name attribute
         name->countryName.value = nameAttribute.data.value;
         name->countryName.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_LOCALITY_NAME_OID, sizeof(X509_LOCALITY_NAME_OID)))
      {
         //Save Locality Name attribute
         name->localityName.value = nameAttribute.data.value;
         name->localityName.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_STATE_OR_PROVINCE_NAME_OID, sizeof(X509_STATE_OR_PROVINCE_NAME_OID)))
      {
         //Save State Or Province Name attribute
         name->stateOrProvinceName.value = nameAttribute.data.value;
         name->stateOrProvinceName.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_ORGANIZATION_NAME_OID, sizeof(X509_ORGANIZATION_NAME_OID)))
      {
         //Save Organization Name attribute
         name->organizationName.value = nameAttribute.data.value;
         name->organizationName.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_ORGANIZATIONAL_UNIT_NAME_OID, sizeof(X509_ORGANIZATIONAL_UNIT_NAME_OID)))
      {
         //Save Organizational Unit Name attribute
         name->organizationalUnitName.value = nameAttribute.data.value;
         name->organizationalUnitName.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_TITLE_OID, sizeof(X509_TITLE_OID)))
      {
         //Save Title attribute
         name->title.value = nameAttribute.data.value;
         name->title.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_NAME_OID, sizeof(X509_NAME_OID)))
      {
         //Save Name attribute
         name->name.value = nameAttribute.data.value;
         name->name.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_GIVEN_NAME_OID, sizeof(X509_GIVEN_NAME_OID)))
      {
         //Save Given Name attribute
         name->givenName.value = nameAttribute.data.value;
         name->givenName.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_INITIALS_OID, sizeof(X509_INITIALS_OID)))
      {
         //Save Initials attribute
         name->initials.value = nameAttribute.data.value;
         name->initials.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_GENERATION_QUALIFIER_OID, sizeof(X509_GENERATION_QUALIFIER_OID)))
      {
         //Save Generation Qualifier attribute
         name->generationQualifier.value = nameAttribute.data.value;
         name->generationQualifier.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_DN_QUALIFIER_OID, sizeof(X509_DN_QUALIFIER_OID)))
      {
         //Save DN Qualifier attribute
         name->dnQualifier.value = nameAttribute.data.value;
         name->dnQualifier.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_PSEUDONYM_OID, sizeof(X509_PSEUDONYM_OID)))
      {
         //Save Pseudonym attribute
         name->pseudonym.value = nameAttribute.data.value;
         name->pseudonym.length = nameAttribute.data.length;
      }
      else if(!oidComp(nameAttribute.oid.value, nameAttribute.oid.length,
         X509_DOMAIN_COMPONENT_OID, sizeof(X509_DOMAIN_COMPONENT_OID)))
      {
         //Save Domain Component attribute
         if(i < X509_MAX_DOMAIN_COMPONENTS)
         {
            name->domainComponents[i].value = nameAttribute.data.value;
            name->domainComponents[i].length = nameAttribute.data.length;
         }

         //Increment the number of domain components
         i++;
      }
      else
      {
         //Discard unknown attributes
      }

      //Next attribute
      data += n;
      length -= n;
   }

   //Save the number of domain components
   name->numDomainComponents = MIN(i, X509_MAX_DOMAIN_COMPONENTS);

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

   //Read AttributeType field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save attribute type
   nameAttribute->oid.value = tag.value;
   nameAttribute->oid.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read AttributeValue field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save ASN.1 string type
   nameAttribute->type = tag.objType;

   //Save attribute value
   nameAttribute->data.value = (char_t *) tag.value;
   nameAttribute->data.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse GeneralNames field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] generalNames Array of GeneralName entries
 * @param[in] maxGeneralNames Maximum number of entries the array can hold
 * @param[out] numGeneralNames Actual number of entries in the array 
 * @return Error code
 **/

error_t x509ParseGeneralNames(const uint8_t *data, size_t length,
   X509GeneralName *generalNames, uint_t maxGeneralNames,
   uint_t *numGeneralNames)
{
   error_t error;
   uint_t i;
   size_t n;
   X509GeneralName generalName;

   //Parse the content of the sequence
   for(i = 0; length > 0; i++)
   {
      //Parse current entry
      error = x509ParseGeneralName(data, length, &n, &generalName);
      //Any error to report?
      if(error)
         return error;

      //Save GeneralName field
      if(i < maxGeneralNames)
      {
         generalNames[i] = generalName;
      }

      //Next field
      data += n;
      length -= n;
   }

   //The sequence must contain at least one entry
   if(i == 0)
      return ERROR_INVALID_SYNTAX;

   //Save the number of GeneralName entries
   *numGeneralNames = MIN(i, maxGeneralNames);

   //Successful processing
   return NO_ERROR;
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

   //Clear the structure
   osMemset(generalName, 0, sizeof(X509GeneralName));

   //Read current item
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Implicit tagging shall be used to encode the GeneralName field
   if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
      return ERROR_INVALID_CLASS;

   //Empty field?
   if(tag.length == 0)
      return ERROR_INVALID_SYNTAX;

   //Save GeneralName field
   generalName->type = (X509GeneralNameType) tag.objType;
   generalName->value = (char_t *) tag.value;
   generalName->length = tag.length;

   //Save the total length of the field
   *totalLength = tag.totalLength;

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
      error = x509ParseInt(tag.value, 2, &value);
      //Any error to report?
      if(error)
         return error;

      //If YY is greater than or equal to 50, the year shall be interpreted
      //as 19YY. If YY is less than 50, the year shall be interpreted as 20YY
      if(value >= 50)
      {
         dateTime->year = 1900 + value;
      }
      else
      {
         dateTime->year = 2000 + value;
      }

      //Point to the next field
      data = tag.value + 2;
   }
   else if(!asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_GENERALIZED_TIME))
   {
      //Check the length of the GeneralizedTime field
      if(tag.length != 15)
         return ERROR_INVALID_SYNTAX;

      //The GeneralizedTime uses a 4-digit representation of the year
      error = x509ParseInt(tag.value, 4, &value);
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
      if(!osIsdigit(*data))
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

#endif
