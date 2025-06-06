/**
 * @file x509_cert_ext_format.c
 * @brief X.509 extension formatting
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
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Format Extensions structure
 * @param[in] extensions Pointer to the X.509 extensions
 * @param[in] subjectKeyId SubjectKeyIdentifier extension
 * @param[in] authKeyId AuthorityKeyIdentifier extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatExtensions(const X509Extensions *extensions,
   const X509SubjectKeyId *subjectKeyId, const X509AuthKeyId *authKeyId,
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

   //Format NetscapeCertType extension
   error = x509FormatNsCertType(&extensions->nsCertType, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format BasicConstraints extension
   error = x509FormatBasicConstraints(&extensions->basicConstraints, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format KeyUsage extension
   error = x509FormatKeyUsage(&extensions->keyUsage, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format ExtendedKeyUsage extension
   error = x509FormatExtendedKeyUsage(&extensions->extKeyUsage, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format SubjectKeyId extension
   error = x509FormatSubjectKeyId(subjectKeyId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format AuthorityKeyId extension
   error = x509FormatAuthorityKeyId(authKeyId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format SubjectAltName extension
   error = x509FormatSubjectAltName(&extensions->subjectAltName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Add custom extensions, if any
   for(i = 0; i < extensions->numCustomExtensions; i++)
   {
      //Format current extension
      error = x509FormatExtension(&extensions->customExtensions[i], p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;
   }

   //Any extensions written?
   if(length > 0)
   {
      //The extensions are encapsulated within a sequence
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
      length = tag.totalLength;

      //Explicit tagging shall be used to encode the Extensions structure
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 3;
      tag.length = length;

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
 * @brief Format X.509 certificate extension
 * @param[in] extension Pointer to the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatExtension(const X509Extension *extension, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t value;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Format the extension identifier
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = extension->oid.length;
   tag.value = extension->oid.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //An extension includes the critical flag, with a default value of FALSE
   if(extension->critical)
   {
      //Mark the extension as critical
      value = 0xFF;

      //Format the critical field
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_BOOLEAN;
      tag.length = 1;
      tag.value = &value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;
   }

   //The extension value is encapsulated in an octet string
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = extension->data.length;
   tag.value = extension->data.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Adjust the length of the extension
   length += n;

   //The extension is encapsulated within a sequence
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
 * @brief Format BasicConstraints extension
 * @param[in] basicConstraints Value of the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatBasicConstraints(const X509BasicConstraints *basicConstraints,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint32_t value;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   uint8_t buffer[3];

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The basic constraints extension identifies whether the subject of the
   //certificate is a CA and the maximum depth of valid certification paths
   //that include this certificate
   if(basicConstraints->cA || basicConstraints->critical)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_BASIC_CONSTRAINTS_OID);
      tag.value = X509_BASIC_CONSTRAINTS_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //An extension includes the critical flag, with a default value of FALSE
      if(basicConstraints->critical)
      {
         //Mark the extension as critical
         buffer[0] = 0xFF;

         //Format the critical field
         tag.constructed = FALSE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_BOOLEAN;
         tag.length = 1;
         tag.value = buffer;

         //Write the corresponding ASN.1 tag
         error = asn1WriteTag(&tag, FALSE, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Total number of bytes that have been written
      *written = length;

      //Length of the extension value
      length = 0;

      //Check whether the cA boolean is set
      if(basicConstraints->cA)
      {
         //The cA boolean indicates whether the certified public key may be used
         //to verify certificate signatures
         buffer[0] = 0xFF;

         //Format the cA field
         tag.constructed = FALSE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_BOOLEAN;
         tag.length = 1;
         tag.value = buffer;

         //Write the corresponding ASN.1 tag
         error = asn1WriteTag(&tag, FALSE, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Where pathLenConstraint does not appear, no limit is imposed
         if(basicConstraints->pathLenConstraint >= 0)
         {
            //The pathLenConstraint field gives the maximum number of non-self-issued
            //intermediate certificates that may follow this certificate in a valid
            //certification path
            value = basicConstraints->pathLenConstraint;

            //Encode pathLenConstraint value
            error = asn1WriteInt32(value, FALSE, p, &n);
            //Any error to report?
            if(error)
               return error;

            //Advance data pointer
            ASN1_INC_POINTER(p, n);
            length += n;
         }
      }

      //Point to the BasicConstraints extension
      if(output != NULL)
      {
         p = output + *written;
      }
      else
      {
         p = NULL;
      }

      //The BasicConstraints extension is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting sequence
      length = tag.totalLength;

      //The extension value is encapsulated in an octet string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the extension
      *written += tag.totalLength;

      //The extension is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = *written;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting sequence
      length = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format KeyUsage extension
 * @param[in] keyUsage Value of the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatKeyUsage(const X509KeyUsage *keyUsage, uint8_t *output,
   size_t *written)
{
   error_t error;
   uint_t k;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   uint8_t buffer[3];

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The key usage extension defines the purpose of the key contained in the
   //certificate
   if(keyUsage->bitmap != 0 || keyUsage->critical)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_KEY_USAGE_OID);
      tag.value = X509_KEY_USAGE_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //An extension includes the critical flag, with a default value of FALSE
      if(keyUsage->critical)
      {
         //Mark the extension as critical
         buffer[0] = 0xFF;

         //Format the critical field
         tag.constructed = FALSE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_BOOLEAN;
         tag.length = 1;
         tag.value = buffer;

         //Write the corresponding ASN.1 tag
         error = asn1WriteTag(&tag, FALSE, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Calculate the length, in bits, of the KeyUsage value
      for(k = 16; k > 0; k--)
      {
         if(keyUsage->bitmap & (1U << (k - 1)))
            break;
      }

      //Total number of bytes needed to encode the KeyUsage value
      n = 0;

      //Encode bit string value
      if(k <= 8)
      {
         buffer[n++] = 8 - k;
         buffer[n++] = reverseInt8(keyUsage->bitmap & 0xFF);
      }
      else
      {
         buffer[n++] = 16 - k;
         buffer[n++] = reverseInt8(keyUsage->bitmap & 0xFF);
         buffer[n++] = reverseInt8((keyUsage->bitmap >> 8) & 0xFF);
      }

      //Format the bit string using ASN.1
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_BIT_STRING;
      tag.length = n;
      tag.value = buffer;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //The extension value is encapsulated in an octet string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the extension
      length += tag.totalLength;

      //The extension is encapsulated within a sequence
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
      length = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ExtendedKeyUsage extension
 * @param[in] extKeyUsage Value of the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatExtendedKeyUsage(const X509ExtendedKeyUsage *extKeyUsage,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t value;
   uint8_t *p;
   Asn1Tag tag;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //This extension indicates one or more purposes for which the certified
   //public key may be used
   if(extKeyUsage->bitmap != 0)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_EXTENDED_KEY_USAGE_OID);
      tag.value = X509_EXTENDED_KEY_USAGE_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //An extension includes the critical flag, with a default value of FALSE
      if(extKeyUsage->critical)
      {
         //Mark the extension as critical
         value = 0xFF;

         //Format the critical field
         tag.constructed = FALSE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_BOOLEAN;
         tag.length = 1;
         tag.value = &value;

         //Write the corresponding ASN.1 tag
         error = asn1WriteTag(&tag, FALSE, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //The extension contains a sequence of KeyPurposeId
      error = x509FormatKeyPurposes(extKeyUsage->bitmap, p, &n);
      //Any error to report?
      if(error)
         return error;

      //The extension value is encapsulated in an octet string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the extension
      length += tag.totalLength;

      //The extension is encapsulated within a sequence
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
      length = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of key purposes
 * @param[in] bitmap Key purposes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatKeyPurposes(uint16_t bitmap, uint8_t *output,
   size_t *written)
{
   error_t error;
   uint_t k;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //If a CA includes extended key usages to satisfy such applications, but
   //does not wish to restrict usages of the key, the CA can include the
   //special KeyPurposeId anyExtendedKeyUsage
   if(bitmap == X509_EXT_KEY_USAGE_ANY)
   {
      //An object identifier is used to identify a given key purpose
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_ANY_EXT_KEY_USAGE_OID);
      tag.value = X509_ANY_EXT_KEY_USAGE_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;
   }
   else
   {
      //Format key purposes
      for(k = 0; k < 16; k++)
      {
         //An object identifier is used to identify a given key purpose
         tag.constructed = FALSE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;

         //Check key purpose
         switch(bitmap & (1U << k))
         {
         //id-kp-serverAuth?
         case X509_EXT_KEY_USAGE_SERVER_AUTH:
            tag.value = X509_KP_SERVER_AUTH_OID;
            tag.length = sizeof(X509_KP_SERVER_AUTH_OID);
            break;

         //id-kp-clientAuth?
         case X509_EXT_KEY_USAGE_CLIENT_AUTH:
            tag.value = X509_KP_CLIENT_AUTH_OID;
            tag.length = sizeof(X509_KP_CLIENT_AUTH_OID);
            break;

         //id-kp-codeSigning?
         case X509_EXT_KEY_USAGE_CODE_SIGNING:
            tag.value = X509_KP_CODE_SIGNING_OID;
            tag.length = sizeof(X509_KP_CODE_SIGNING_OID);
            break;

         //id-kp-emailProtection?
         case X509_EXT_KEY_USAGE_EMAIL_PROTECTION:
            tag.value = X509_KP_EMAIL_PROTECTION_OID;
            tag.length = sizeof(X509_KP_EMAIL_PROTECTION_OID);
            break;

         //id-kp-ipsecEndSystem?
         case X509_EXT_KEY_USAGE_IPSEC_END_SYSTEM:
            tag.value = X509_KP_IPSEC_END_SYSTEM_OID;
            tag.length = sizeof(X509_KP_IPSEC_END_SYSTEM_OID);
            break;

         //id-kp-ipsecTunnel?
         case X509_EXT_KEY_USAGE_IPSEC_TUNNEL:
            tag.value = X509_KP_IPSEC_TUNNEL_OID;
            tag.length = sizeof(X509_KP_IPSEC_TUNNEL_OID);
            break;

         //id-kp-ipsecUser?
         case X509_EXT_KEY_USAGE_IPSEC_USER:
            tag.value = X509_KP_IPSEC_USER_OID;
            tag.length = sizeof(X509_KP_IPSEC_USER_OID);
            break;

         //id-kp-timeStamping?
         case X509_EXT_KEY_USAGE_TIME_STAMPING:
            tag.value = X509_KP_TIME_STAMPING_OID;
            tag.length = sizeof(X509_KP_TIME_STAMPING_OID);
            break;

         //id-kp-OCSPSigning?
         case X509_EXT_KEY_USAGE_OCSP_SIGNING:
            tag.value = X509_KP_OCSP_SIGNING_OID;
            tag.length = sizeof(X509_KP_OCSP_SIGNING_OID);
            break;

         //id-kp-ipsecIKE?
         case X509_EXT_KEY_USAGE_IPSEC_IKE:
            tag.value = X509_KP_IPSEC_IKE_OID;
            tag.length = sizeof(X509_KP_IPSEC_IKE_OID);
            break;

         //id-kp-secureShellClient?
         case X509_EXT_KEY_USAGE_SSH_CLIENT:
            tag.value = X509_KP_SSH_CLIENT_OID;
            tag.length = sizeof(X509_KP_SSH_CLIENT_OID);
            break;

         //id-kp-secureShellServer?
         case X509_EXT_KEY_USAGE_SSH_SERVER:
            tag.value = X509_KP_SSH_SERVER_OID;
            tag.length = sizeof(X509_KP_SSH_SERVER_OID);
            break;

         //id-kp-documentSigning?
         case X509_EXT_KEY_USAGE_DOC_SIGNING:
            tag.value = X509_KP_DOC_SIGNING_OID;
            tag.length = sizeof(X509_KP_DOC_SIGNING_OID);
            break;

         //Unknown key purpose?
         default:
            tag.value = NULL;
            tag.length = 0;
            break;
         }

         //Valid object identifier?
         if(tag.value != NULL && tag.length > 0)
         {
            //Write the corresponding ASN.1 tag
            error = asn1WriteTag(&tag, FALSE, p, &n);
            //Any error to report?
            if(error)
               return error;

            //Advance data pointer
            ASN1_INC_POINTER(p, n);
            length += n;
         }
      }
   }

   //The key purposes are encapsulated within a sequence
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
 * @brief Format SubjectAltName extension
 * @param[in] subjectAltName Value of the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatSubjectAltName(const X509SubjectAltName *subjectAltName,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The subject alternative name extension allows identities to be bound to the
   //subject of the certificate. These identities may be included in addition
   //to or in place of the identity in the subject field of the certificate
   if(subjectAltName->numGeneralNames > 0)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_SUBJECT_ALT_NAME_OID);
      tag.value = X509_SUBJECT_ALT_NAME_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      //Total number of bytes that have been written
      *written = n;

      //Loop through subject alternative names
      for(i = 0; i < subjectAltName->numGeneralNames; i++)
      {
         //Format the current name
         tag.constructed = FALSE;
         tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
         tag.objType = subjectAltName->generalNames[i].type;
         tag.length = subjectAltName->generalNames[i].length;
         tag.value = (uint8_t *) subjectAltName->generalNames[i].value;

         //Write the corresponding ASN.1 tag
         error = asn1WriteTag(&tag, FALSE, p, &n);
         //Any error to report?
         if(error)
            return error;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Point to the first object
      if(output != NULL)
      {
         p = output + *written;
      }
      else
      {
         p = NULL;
      }

      //The names are encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting sequence
      length = tag.totalLength;

      //The extension value is encapsulated in an octet string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the extension
      *written += tag.totalLength;

      //The extension is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = *written;

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
 * @brief Format SubjectKeyIdentifier extension
 * @param[in] subjectKeyId Value of the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatSubjectKeyId(const X509SubjectKeyId *subjectKeyId,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The subject key identifier extension provides a means of identifying
   //certificates that contain a particular public key
   if(subjectKeyId->value != NULL && subjectKeyId->length > 0)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_SUBJECT_KEY_ID_OID);
      tag.value = X509_SUBJECT_KEY_ID_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Format the KeyIdentifier field
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = subjectKeyId->length;
      tag.value = subjectKeyId->value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //The extension value is encapsulated in an octet string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the extension
      length += tag.totalLength;

      //The extension is encapsulated within a sequence
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
      length = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format AuthorityKeyIdentifier extension
 * @param[in] authKeyId Value of the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatAuthorityKeyId(const X509AuthKeyId *authKeyId,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The authority key identifier extension provides a means of identifying the
   //public key corresponding to the private key used to sign a certificate
   if(authKeyId->keyId.value != NULL && authKeyId->keyId.length > 0)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_AUTHORITY_KEY_ID_OID);
      tag.value = X509_AUTHORITY_KEY_ID_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Explicit tagging shall be used to encode the keyIdentifier field
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 0;
      tag.length = authKeyId->keyId.length;
      tag.value = authKeyId->keyId.value;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //The KeyIdentifier field is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Get the length of the resulting sequence
      n = tag.totalLength;

      //The extension value is encapsulated in an octet string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the extension
      length += tag.totalLength;

      //The extension is encapsulated within a sequence
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
      length = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format NetscapeCertType extension
 * @param[in] nsCertType Value of the extension
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t x509FormatNsCertType(const X509NsCertType *nsCertType,
   uint8_t *output, size_t *written)
{
   error_t error;
   uint_t k;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   uint8_t buffer[2];

   //Initialize status code
   error = NO_ERROR;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //The NetscapeCertType extension limit the use of a certificate
   if(nsCertType->bitmap != 0)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(X509_NS_CERT_TYPE_OID);
      tag.value = X509_NS_CERT_TYPE_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //Calculate the length, in bits, of the NetscapeCertType value
      for(k = 8; k > 0; k--)
      {
         if(nsCertType->bitmap & (1U << (k - 1)))
            break;
      }

      //Encode bit string value
      buffer[0] = 8 - k;
      buffer[1] = reverseInt8(nsCertType->bitmap);

      //Format the bit string using ASN.1
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_BIT_STRING;
      tag.length = sizeof(buffer);
      tag.value = buffer;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //The extension value is encapsulated in an octet string
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = n;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Adjust the length of the extension
      length += tag.totalLength;

      //The extension is encapsulated within a sequence
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
      length = tag.totalLength;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}

#endif
