/**
 * @file x509_cert_ext_parse.c
 * @brief X.509 extension parsing
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
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_ext_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Parse X.509 certificate extensions
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] extensions Information resulting from the parsing process
 * @param[in] options Certificate parsing options
 * @return Error code
 **/

error_t x509ParseCertExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509Extensions *extensions, const X509Options *options)
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
   extensions->raw.value = tag.value;
   extensions->raw.length = tag.length;

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

      //Jump to the next extension
      data += n;
      length -= n;

      //Test if the current extension is a duplicate
      error = x509CheckDuplicateExtension(extension.oid.value,
         extension.oid.length, data, length);
      //Duplicate extension found?
      if(error)
         return error;

      //Check extension identifier
      if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_BASIC_CONSTRAINTS_OID) == 0)
      {
         //Parse BasicConstraints extension
         error = x509ParseBasicConstraints(extension.critical, extension.data.value,
            extension.data.length, &extensions->basicConstraints);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_NAME_CONSTRAINTS_OID) == 0)
      {
         //Parse NameConstraints extension
         error = x509ParseNameConstraints(extension.critical, extension.data.value,
            extension.data.length, &extensions->nameConstraints);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_KEY_USAGE_OID) == 0)
      {
         //Parse KeyUsage extension
         error = x509ParseKeyUsage(extension.critical, extension.data.value,
            extension.data.length, &extensions->keyUsage);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_EXTENDED_KEY_USAGE_OID) == 0)
      {
         //Parse ExtendedKeyUsage extension
         error = x509ParseExtendedKeyUsage(extension.critical, extension.data.value,
            extension.data.length, &extensions->extKeyUsage);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_SUBJECT_ALT_NAME_OID) == 0)
      {
         //Parse SubjectAltName extension
         error = x509ParseSubjectAltName(extension.critical, extension.data.value,
            extension.data.length, &extensions->subjectAltName);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_SUBJECT_KEY_ID_OID) == 0)
      {
         //Parse SubjectKeyIdentifier extension
         error = x509ParseSubjectKeyId(extension.critical, extension.data.value,
            extension.data.length, &extensions->subjectKeyId);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_AUTHORITY_KEY_ID_OID) == 0)
      {
         //Parse AuthorityKeyIdentifier extension
         error = x509ParseAuthKeyId(extension.critical, extension.data.value,
            extension.data.length, &extensions->authKeyId);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_CRL_DISTR_POINTS_OID) == 0)
      {
         //Parse CRLDistributionPoints extension
         error = x509ParseCrlDistrPoints(extension.critical, extension.data.value,
            extension.data.length, &extensions->crlDistrPoints);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_AUTH_INFO_ACCESS_OID) == 0)
      {
         //Parse AuthorityInformationAccess extension
         error = x509ParseAuthInfoAccess(extension.critical, extension.data.value,
            extension.data.length, &extensions->authInfoAccess);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_PKIX_OCSP_NO_CHECK_OID) == 0)
      {
         //Parse PkixOcspNoCheck extension
         error = x509ParsePkixOcspNoCheck(extension.critical, extension.data.value,
            extension.data.length, &extensions->pkixOcspNoCheck);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_NS_CERT_TYPE_OID) == 0)
      {
         //Parse NetscapeCertType extension
         error = x509ParseNsCertType(extension.critical, extension.data.value,
            extension.data.length, &extensions->nsCertType);
      }
      else
      {
         //Parse unknown extension
         error = x509ParseUnknownCertExtension(extension.oid.value,
            extension.oid.length, extension.critical, extension.data.value,
            extension.data.length, extensions);

         //Check status code
         if(error == ERROR_UNSUPPORTED_EXTENSION)
         {
            //An application must reject the certificate if it encounters a
            //critical extension it does not recognize or a critical extension
            //that contains information that it cannot process
            if(!extension.critical || options->ignoreUnknownExtensions)
            {
               error = NO_ERROR;
            }
         }
      }

      //Any parsing error?
      if(error)
         return error;
   }

   //Check whether the NameConstraints extension is present
   if(extensions->nameConstraints.permittedSubtrees.length > 0 ||
      extensions->nameConstraints.excludedSubtrees.length > 0)
   {
      //The NameConstraints extension, must be used only in a CA certificate
      //(refer to RFC 5280, section 4.2.1.10)
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
   extension->oid.value = tag.value;
   extension->oid.length = tag.length;

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
   extension->data.value = tag.value;
   extension->data.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse BasicConstraints extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] basicConstraints Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseBasicConstraints(bool_t critical, const uint8_t *data,
   size_t length, X509BasicConstraints *basicConstraints)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing BasicConstraints...\r\n");

   //An extension can be marked as critical
   basicConstraints->critical = critical;

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
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] nameConstraints Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseNameConstraints(bool_t critical, const uint8_t *data,
   size_t length, X509NameConstraints *nameConstraints)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing NameConstraints...\r\n");

   //An extension can be marked as critical
   nameConstraints->critical = critical;

   //Conforming CAs must mark the NameConstraints extension as critical (refer
   //to RFC 5280, section 4.2.1.10)
   if(!nameConstraints->critical)
      return ERROR_INVALID_SYNTAX;

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

      //Implicit tagging shall be used to encode the GeneralSubtrees field
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
         nameConstraints->permittedSubtrees.value = tag.value;
         nameConstraints->permittedSubtrees.length = tag.length;
      }
      else if(tag.objType == 1)
      {
         //Parse the excludedSubtrees field
         error = x509ParseGeneralSubtrees(tag.value, tag.length);
         //Any error to report?
         if(error)
            return error;

         //Raw contents of the ASN.1 sequence
         nameConstraints->excludedSubtrees.value = tag.value;
         nameConstraints->excludedSubtrees.length = tag.length;
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
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t x509ParsePolicyConstraints(bool_t critical, const uint8_t *data,
   size_t length)
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
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t x509ParsePolicyMappings(bool_t critical, const uint8_t *data,
   size_t length)
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
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t x509ParseInhibitAnyPolicy(bool_t critical, const uint8_t *data,
   size_t length)
{
   //Debug message
   TRACE_DEBUG("      Parsing InhibitAnyPolicy...\r\n");

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse KeyUsage extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] keyUsage Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseKeyUsage(bool_t critical, const uint8_t *data,
   size_t length, X509KeyUsage *keyUsage)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing KeyUsage...\r\n");

   //An extension can be marked as critical
   keyUsage->critical = critical;

   //The key usage extension defines the purpose of the key contained in the
   //certificate
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_BIT_STRING);
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
   keyUsage->bitmap = 0;

   //Read bits b0 to b7
   if(tag.length >= 2)
   {
      keyUsage->bitmap |= reverseInt8(tag.value[1]);
   }

   //Read bits b8 to b15
   if(tag.length >= 3)
   {
      keyUsage->bitmap |= reverseInt8(tag.value[2]) << 8;
   }

   //When the key usage extension appears in a certificate, at least one of
   //the bits must be set to 1 (refer to RFC 5280, section 4.2.1.3)
   if(keyUsage->bitmap == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ExtendedKeyUsage extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] extKeyUsage Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseExtendedKeyUsage(bool_t critical, const uint8_t *data,
   size_t length, X509ExtendedKeyUsage *extKeyUsage)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing ExtendedKeyUsage...\r\n");

   //An extension can be marked as critical
   extKeyUsage->critical = critical;

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
      if(OID_COMP(tag.value, tag.length, X509_ANY_EXT_KEY_USAGE_OID) == 0)
      {
         //If a CA includes extended key usages to satisfy such applications,
         //but does not wish to restrict usages of the key, the CA can include
         //the special KeyPurposeId anyExtendedKeyUsage
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_ANY;
      }
      //id-kp-serverAuth?
      else if(OID_COMP(tag.value, tag.length, X509_KP_SERVER_AUTH_OID) == 0)
      {
         //TLS WWW server authentication
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_SERVER_AUTH;
      }
      //id-kp-clientAuth?
      else if(OID_COMP(tag.value, tag.length, X509_KP_CLIENT_AUTH_OID) == 0)
      {
         //TLS WWW client authentication
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_CLIENT_AUTH;
      }
      //id-kp-codeSigning?
      else if(OID_COMP(tag.value, tag.length, X509_KP_CODE_SIGNING_OID) == 0)
      {
         //Signing of downloadable executable code
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_CODE_SIGNING;
      }
      //id-kp-emailProtection?
      else if(OID_COMP(tag.value, tag.length, X509_KP_EMAIL_PROTECTION_OID) == 0)
      {
         //Email protection
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_EMAIL_PROTECTION;
      }
      //id-kp-ipsecEndSystem?
      else if(OID_COMP(tag.value, tag.length, X509_KP_IPSEC_END_SYSTEM_OID) == 0)
      {
         //IPsec end system
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_IPSEC_END_SYSTEM;
      }
      //id-kp-ipsecTunnel?
      else if(OID_COMP(tag.value, tag.length, X509_KP_IPSEC_TUNNEL_OID) == 0)
      {
         //IPsec tunnel
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_IPSEC_TUNNEL;
      }
      //id-kp-ipsecUser?
      else if(OID_COMP(tag.value, tag.length, X509_KP_IPSEC_USER_OID) == 0)
      {
         //IPsec user
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_IPSEC_USER;
      }
      //id-kp-timeStamping?
      else if(OID_COMP(tag.value, tag.length, X509_KP_TIME_STAMPING_OID) == 0)
      {
         //Binding the hash of an object to a time
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_TIME_STAMPING;
      }
      //id-kp-OCSPSigning?
      else if(OID_COMP(tag.value, tag.length, X509_KP_OCSP_SIGNING_OID) == 0)
      {
         //Signing OCSP responses
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_OCSP_SIGNING;
      }
      //id-kp-ipsecIKE?
      else if(OID_COMP(tag.value, tag.length, X509_KP_IPSEC_IKE_OID) == 0)
      {
         //The certificate is intended to be used with IKE
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_IPSEC_IKE;
      }
      //id-kp-secureShellClient?
      else if(OID_COMP(tag.value, tag.length, X509_KP_SSH_CLIENT_OID) == 0)
      {
         //The key can be used for a Secure Shell client
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_SSH_CLIENT;
      }
      //id-kp-secureShellServer?
      else if(OID_COMP(tag.value, tag.length, X509_KP_SSH_SERVER_OID) == 0)
      {
         //The key can be used for a Secure Shell server
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_SSH_SERVER;
      }
      //id-kp-documentSigning?
      else if(OID_COMP(tag.value, tag.length, X509_KP_DOC_SIGNING_OID) == 0)
      {
         //The public key encoded in the certificate has been certified to be
         //used for cryptographic operations on contents that are consumed by
         //people (refer to RFC 9336, section 3.1)
         extKeyUsage->bitmap |= X509_EXT_KEY_USAGE_DOC_SIGNING;
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
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] subjectAltName Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectAltName(bool_t critical, const uint8_t *data,
   size_t length, X509SubjectAltName *subjectAltName)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing SubjectAltName...\r\n");

   //An extension can be marked as critical
   subjectAltName->critical = critical;

   //The SubjectAltName structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   subjectAltName->raw.value = tag.value;
   subjectAltName->raw.length = tag.length;

   //The subject alternative name extension allows identities to be bound to the
   //subject of the certificate. These identities may be included in addition
   //to or in place of the identity in the subject field of the certificate
   return x509ParseGeneralNames(tag.value, tag.length,
      subjectAltName->generalNames, X509_MAX_SUBJECT_ALT_NAMES,
      &subjectAltName->numGeneralNames);
}


/**
 * @brief Parse SubjectKeyIdentifier extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] subjectKeyId Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectKeyId(bool_t critical, const uint8_t *data,
   size_t length, X509SubjectKeyId *subjectKeyId)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing SubjectKeyIdentifier...\r\n");

   //An extension can be marked as critical
   subjectKeyId->critical = critical;

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
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] authKeyId Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAuthKeyId(bool_t critical, const uint8_t *data,
   size_t length, X509AuthKeyId *authKeyId)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing AuthorityKeyIdentifier...\r\n");

   //An extension can be marked as critical
   authKeyId->critical = critical;

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

      //Implicit tagging shall be used to encode the item
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //keyIdentifier object found?
      if(tag.objType == 0)
      {
         //Save the authority key identifier
         authKeyId->keyId.value = tag.value;
         authKeyId->keyId.length = tag.length;
      }

      //Next item
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CRLDistributionPoints extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] crlDistrPoints Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlDistrPoints(bool_t critical, const uint8_t *data,
   size_t length, X509CrlDistrPoints *crlDistrPoints)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509DistrPoint distrPoint;

   //Debug message
   TRACE_DEBUG("      Parsing CRLDistributionPoints...\r\n");

   //An extension can be marked as critical
   crlDistrPoints->critical = critical;

   //The CRLDistributionPoints structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   crlDistrPoints->raw.value = tag.value;
   crlDistrPoints->raw.length = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Parse the content of the sequence
   for(i = 0; length > 0; i++)
   {
      //Parse DistributionPoint field
      error = x509ParseDistrPoint(data, length, &n, &distrPoint);
      //Any error to report?
      if(error)
         return error;

      //Save distribution point
      if(i < X509_MAX_DISTR_POINTS)
      {
         crlDistrPoints->distrPoints[i] = distrPoint;
      }

      //Next item
      data += n;
      length -= n;
   }

   //If the CRLDistributionPoints extension is present, the sequence must
   //contain at least one entry (refer to RFC 5280, section 4.2.1.13)
   if(i == 0)
      return ERROR_INVALID_SYNTAX;

   //Save the number of distribution points
   crlDistrPoints->numDistrPoints = MIN(i, X509_MAX_DISTR_POINTS);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DistributionPoint field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] distrPoint Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDistrPoint(const uint8_t *data, size_t length,
   size_t *totalLength, X509DistrPoint *distrPoint)
{
   error_t error;
   Asn1Tag tag;

   //Clear the structure
   osMemset(distrPoint, 0, sizeof(X509DistrPoint));

   //The DistributionPoint structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

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

      //Implicit tagging shall be used to encode the item
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //A DistributionPoint consists of three fields, each of which is optional
      if(tag.objType == 0)
      {
         //Parse DistributionPointName field
         error = x509ParseDistrPointName(tag.value, tag.length,
            &distrPoint->distrPointName);
      }
      else if(tag.objType == 1)
      {
         //Parse ReasonFlags field
         error = x509ParseReasonFlags(tag.value, tag.length,
            &distrPoint->reasonFlags);
      }
      else if(tag.objType == 2)
      {
         //Parse CRLIssuer field
         error = x509ParseGeneralNames(tag.value, tag.length,
            distrPoint->crlIssuers, X509_MAX_CRL_ISSUERS,
            &distrPoint->numCrlIssuers);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_TYPE;
      }

      //Any error to report?
      if(error)
         return error;

      //Next item
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DistributionPointName field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] distrPointName Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDistrPointName(const uint8_t *data, size_t length,
   X509DistrPointName *distrPointName)
{
   error_t error;
   Asn1Tag tag;

   //Parse ASN.1 tag
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Implicit tagging shall be used to encode the item
   if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
      return ERROR_INVALID_CLASS;

   //When the distributionPoint field is present, it contains either a
   //sequence of general names or a single value, nameRelativeToCRLIssuer
   if(tag.objType == 0)
   {
      //Parse fullName field
      error = x509ParseGeneralNames(tag.value, tag.length,
         distrPointName->fullNames, X509_MAX_FULL_NAMES,
         &distrPointName->numFullNames);
   }
   else if(tag.objType == 1)
   {
      //Parse nameRelativeToCRLIssuer field
      error = x509ParseRelativeName(tag.value, tag.length,
         &distrPointName->relativeName);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse nameRelativeToCRLIssuer field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] relativeName Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRelativeName(const uint8_t *data, size_t length,
   X509NameAttribute *relativeName)
{
   error_t error;
   Asn1Tag tag;

   //Read the first field of the set
   error = asn1ReadSequence(data, length, &tag);
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
   relativeName->oid.value = tag.value;
   relativeName->oid.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read AttributeValue field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save ASN.1 string type
   relativeName->type = tag.objType;

   //Save attribute value
   relativeName->data.value = (char_t *) tag.value;
   relativeName->data.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ReasonFlags field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] reasonFlags Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseReasonFlags(const uint8_t *data, size_t length,
   uint16_t *reasonFlags)
{
   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(length < 1)
      return ERROR_INVALID_SYNTAX;

   //Sanity check
   if(data[0] >= 8)
      return ERROR_INVALID_SYNTAX;

   //Clear bit string
   *reasonFlags = 0;

   //Read bits b0 to b7
   if(length >= 2)
   {
      *reasonFlags |= reverseInt8(data[1]);
   }

   //Read bits b8 to b15
   if(length >= 3)
   {
      *reasonFlags |= reverseInt8(data[2]) << 8;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse AuthorityInformationAccess extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] authInfoAccess Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAuthInfoAccess(bool_t critical, const uint8_t *data,
   size_t length, X509AuthInfoAccess *authInfoAccess)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509AccessDescription accessDescription;

   //Debug message
   TRACE_DEBUG("      Parsing AuthorityInformationAccess...\r\n");

   //An extension can be marked as critical
   authInfoAccess->critical = critical;

   //The AuthorityInformationAccess structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   authInfoAccess->raw.value = tag.value;
   authInfoAccess->raw.length = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Parse the content of the sequence
   for(i = 0; length > 0; i++)
   {
      //Parse AccessDescription field
      error = x509ParseAccessDescription(data, length, &n, &accessDescription);
      //Any error to report?
      if(error)
         return error;

      //Save access description
      if(i < X509_MAX_ACCESS_DESCRIPTIONS)
      {
         authInfoAccess->accessDescriptions[i] = accessDescription;
      }

      //Next item
      data += n;
      length -= n;
   }

   //If the AuthorityInformationAccess extension is present, the sequence must
   //contain at least one entry (refer to RFC 5280, section 4.2.2.1)
   if(i == 0)
      return ERROR_INVALID_SYNTAX;

   //Save the number of access descriptions
   authInfoAccess->numAccessDescriptions = MIN(i, X509_MAX_ACCESS_DESCRIPTIONS);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse AccessDescription field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] accessDescription Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAccessDescription(const uint8_t *data, size_t length,
   size_t *totalLength, X509AccessDescription *accessDescription)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Clear the structure
   osMemset(accessDescription, 0, sizeof(X509AccessDescription));

   //The AccessDescription structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Read accessMethod field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The type and format of the information are specified by the accessMethod
   //field (refer to RFC 5280, section 4.2.2.1)
   accessDescription->accessMethod.value = tag.value;
   accessDescription->accessMethod.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //The accessLocation field specifies the location of the information
   error = x509ParseGeneralName(data, length, &n,
      &accessDescription->accessLocation);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PkixOcspNoCheck extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] pkixOcspNoCheck Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParsePkixOcspNoCheck(bool_t critical, const uint8_t *data,
   size_t length, X509PkixOcspNoCheck *pkixOcspNoCheck)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing PkixOcspNoCheck...\r\n");

   //The extension should be a non-critical extension
   pkixOcspNoCheck->critical = critical;

   //The value of the extension shall be NULL (refer to RFC 6960,
   //section 4.2.2.2.1)
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_NULL);
   //Invalid tag?
   if(error)
      return error;

   //The certificate contains a valid id-pkix-ocsp-nocheck extension
   pkixOcspNoCheck->present = TRUE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse NetscapeCertType extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] nsCertType Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseNsCertType(bool_t critical, const uint8_t *data,
   size_t length, X509NsCertType *nsCertType)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing NetscapeCertType...\r\n");

   //An extension can be marked as critical
   nsCertType->critical = critical;

   //The NetscapeCertType extension limit the use of a certificate
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_BIT_STRING);
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
   nsCertType->bitmap = 0;

   //Read bits b0 to b7
   if(tag.length >= 2)
   {
      nsCertType->bitmap |= reverseInt8(tag.value[1]);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse unknown X.509 certificate extension
 * @param[in] oid Extension identifier
 * @param[in] oidLen Length of the extension identifier
 * @param[in] critical Critical extension flag
 * @param[in] data Extension value
 * @param[in] dataLen Length of the extension value
 * @param[out] extensions Information resulting from the parsing process
 * @return Error code
 **/

__weak_func error_t x509ParseUnknownCertExtension(const uint8_t *oid,
   size_t oidLen, bool_t critical, const uint8_t *data, size_t dataLen,
   X509Extensions *extensions)
{
   //The extension is not supported
   return ERROR_UNSUPPORTED_EXTENSION;
}


/**
 * @brief Check whether the specified extension is a duplicate
 * @param[in] oid Extension identifier
 * @param[in] oidLen Length of the extension identifier
 * @param[in] data Pointer to the extension list
 * @param[in] length Length of the extension list
 * @return Error code
 **/

error_t x509CheckDuplicateExtension(const uint8_t *oid, size_t oidLen,
   const uint8_t *data, size_t length)
{
   error_t error;
   size_t n;
   X509Extension extension;

   //Loop through the extensions
   while(length > 0)
   {
      //Each extension includes an OID and a value
      error = x509ParseExtension(data, length, &n, &extension);
      //Any error to report?
      if(error)
         return error;

      //A certificate must not include more than one instance of a particular
      //extension (refer to RFC 5280, section 4.2)
      if(oidComp(extension.oid.value, extension.oid.length, oid, oidLen) == 0)
      {
         return ERROR_INVALID_SYNTAX;
      }

      //Jump to the next extension
      data += n;
      length -= n;
   }

   //Successful verification
   return NO_ERROR;
}

#endif
