/**
 * @file x509_crl_ext_parse.c
 * @brief CRL extension parsing
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
#include "pkix/x509_crl_parse.h"
#include "pkix/x509_crl_ext_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Parse CRL extensions
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] crlExtensions Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509CrlExtensions *crlExtensions)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //No more data to process?
   if(length == 0)
   {
      //The CrlExtensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Explicit tagging is used to encode the CrlExtensions field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
   //Invalid tag?
   if(error)
   {
      //The CrlExtensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Debug message
   TRACE_DEBUG("    Parsing CrlExtensions...\r\n");

   //This field is a sequence of one or more CRL extensions
   error = asn1ReadSequence(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   crlExtensions->raw.value = tag.value;
   crlExtensions->raw.length = tag.length;

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
         X509_CRL_NUMBER_OID) == 0)
      {
         //Parse CRLNumber extension
         error = x509ParseCrlNumber(extension.critical, extension.data.value,
            extension.data.length, &crlExtensions->crlNumber);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_DELTA_CRL_INDICATOR_OID) == 0)
      {
         //Parse DeltaCRLIndicator extension
         error = x509ParseDeltaCrlIndicator(extension.critical, extension.data.value,
            extension.data.length, &crlExtensions->deltaCrlIndicator);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_ISSUING_DISTR_POINT_OID) == 0)
      {
         //Parse IssuingDistributionPoint extension
         error = x509ParseIssuingDistrPoint(extension.critical, extension.data.value,
            extension.data.length, &crlExtensions->issuingDistrPoint);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_AUTHORITY_KEY_ID_OID) == 0)
      {
         //Parse AuthorityKeyIdentifier extension
         error = x509ParseAuthKeyId(extension.critical, extension.data.value,
            extension.data.length, &crlExtensions->authKeyId);
      }
      else
      {
         //Parse unknown extension
         error = x509ParseUnknownCrlExtension(extension.oid.value,
            extension.oid.length, extension.critical, extension.data.value,
            extension.data.length, crlExtensions);

         //Check status code
         if(error == ERROR_UNSUPPORTED_EXTENSION)
         {
            //If a CRL contains a critical extension that the application cannot
            //process, then the application must not use that CRL to determine
            //the status of certificates (refer to RFC 5280, section 5.2)
            if(!extension.critical)
            {
               error = NO_ERROR;
            }
         }
      }

      //Any parsing error?
      if(error)
         return error;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CRLNumber extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] crlNumber Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlNumber(bool_t critical, const uint8_t *data,
   size_t length, X509CrlNumber *crlNumber)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing CRLNumber...\r\n");

   //An CRL extension can be marked as critical
   crlNumber->critical = critical;

   //Read CRLNumber structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the CRL number
   crlNumber->value = tag.value;
   crlNumber->length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DeltaCRLIndicator extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] deltaCrlIndicator Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDeltaCrlIndicator(bool_t critical, const uint8_t *data,
   size_t length, X509DeltaCrlIndicator *deltaCrlIndicator)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing DeltaCRLIndicator...\r\n");

   //An CRL extension can be marked as critical
   deltaCrlIndicator->critical = critical;

   //Read BaseCRLNumber structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the CRL number
   deltaCrlIndicator->baseCrlNumber.value = tag.value;
   deltaCrlIndicator->baseCrlNumber.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse IssuingDistributionPoint extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] issuingDistrPoint Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseIssuingDistrPoint(bool_t critical, const uint8_t *data,
   size_t length, X509IssuingDistrPoint *issuingDistrPoint)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing IssuingDistributionPoint...\r\n");

   //An CRL extension can be marked as critical
   issuingDistrPoint->critical = critical;

   //The IssuingDistributionPoint extension is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first subfield of the sequence
   data = tag.value;
   length = tag.length;

   //The issuing distribution point is a critical CRL extension that identifies
   //the CRL distribution point and scope for a particular CRL, and it indicates
   //whether the CRL covers revocation for end entity certificates only, CA
   //certificates only, attribute certificates only, or a limited set of reason
   //codes
   while(length > 0)
   {
      //Read current subfield
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Implicit tagging shall be used to encode each subfield
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //Check subfield type
      if(tag.objType == 0)
      {
         //Parse distributionPoint subfield
      }
      else if(tag.objType == 1)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the onlyContainsUserCerts subfield
         issuingDistrPoint->onlyContainsUserCerts = tag.value[0] ? TRUE : FALSE;
      }
      else if(tag.objType == 2)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the onlyContainsCACerts subfield
         issuingDistrPoint->onlyContainsCaCerts = tag.value[0] ? TRUE : FALSE;
      }
      else if(tag.objType == 3)
      {
         //Parse onlySomeReasons subfield
      }
      else if(tag.objType == 4)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the indirectCRL subfield
         issuingDistrPoint->indirectCrl = tag.value[0] ? TRUE : FALSE;
      }
      else if(tag.objType == 5)
      {
         //Make sure the length of the boolean is valid
         if(tag.length != 1)
            return ERROR_INVALID_SYNTAX;

         //Save the value of the onlyContainsAttributeCerts subfield
         issuingDistrPoint->onlyContainsAttributeCerts = tag.value[0] ? TRUE : FALSE;
      }
      else
      {
         //Discard unknown subfields
      }

      //Next subfield
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CRL entry extensions
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] crlEntryExtensions Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrlEntryExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509CrlEntryExtensions *crlEntryExtensions)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //No more data to process?
   if(length == 0)
   {
      //The CrlEntryExtensions field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Debug message
   TRACE_DEBUG("    Parsing CrlEntryExtensions...\r\n");

   //This field is a sequence of one or more CRL entry extensions
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the CrlEntryExtensions field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   crlEntryExtensions->raw.value = tag.value;
   crlEntryExtensions->raw.length = tag.length;

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
         X509_REASON_CODE_OID) == 0)
      {
         //Parse ReasonCode extension
         error = x509ParseReasonCode(extension.critical, extension.data.value,
            extension.data.length, &crlEntryExtensions->reasonCode);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_INVALIDITY_DATE_OID) == 0)
      {
         //Parse InvalidityDate extension
         error = x509ParseInvalidityDate(extension.critical, extension.data.value,
            extension.data.length, &crlEntryExtensions->invalidityDate);
      }
      else if(OID_COMP(extension.oid.value, extension.oid.length,
         X509_CERTIFICATE_ISSUER_OID) == 0)
      {
         //Parse CertificateIssuer extension
         error = x509ParseCertificateIssuer(extension.critical, extension.data.value,
            extension.data.length, &crlEntryExtensions->certIssuer);
      }
      else
      {
         //Check if the extension is marked as critical
         if(extension.critical)
         {
            //If a CRL contains a critical CRL entry extension that the
            //application cannot process, then the application must not use
            //that CRL to determine the status of any certificates
            error = ERROR_UNSUPPORTED_EXTENSION;
         }
      }

      //Any parsing error?
      if(error)
         return error;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ReasonCode entry extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] reasonCode Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseReasonCode(bool_t critical, const uint8_t *data,
   size_t length, X509CrlReason *reasonCode)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing ReasonCode...\r\n");

   //An CRL entry extension can be marked as critical
   reasonCode->critical = critical;

   //Read ReasonCode field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_ENUMERATED);
   //Invalid tag?
   if(error)
      return error;

   //Check the length of the field
   if(tag.length != 1)
      return ERROR_INVALID_SYNTAX;

   //The ReasonCode is a non-critical CRL entry extension that identifies
   //the reason for the certificate revocation
   reasonCode->value = tag.value[0];

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse InvalidityDate entry extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] invalidityDate Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseInvalidityDate(bool_t critical, const uint8_t *data,
   size_t length, X509InvalidityDate *invalidityDate)
{
   error_t error;
   size_t n;

   //Debug message
   TRACE_DEBUG("      Parsing InvalidityDate...\r\n");

   //An CRL entry extension can be marked as critical
   invalidityDate->critical = critical;

   //Read InvalidityDate field
   error = x509ParseTime(data, length, &n, &invalidityDate->value);

   //Return status code
   return error;
}


/**
 * @brief Parse CertificateIssuer entry extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certificateIssuer Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCertificateIssuer(bool_t critical, const uint8_t *data,
   size_t length, X509CertificateIssuer *certificateIssuer)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;
   X509GeneralName generalName;

   //Debug message
   TRACE_DEBUG("      Parsing CertificateIssuer...\r\n");

   //An CRL entry extension can be marked as critical
   certificateIssuer->critical = critical;

   //The CertificateIssuer structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   certificateIssuer->raw.value = tag.value;
   certificateIssuer->raw.length = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //This CRL entry extension identifies the certificate issuer associated
   //with an entry in an indirect CRL, that is, a CRL that has the indirectCRL
   //indicator set in its issuing distribution point extension
   for(i = 0; length > 0; i++)
   {
      //Parse GeneralName field
      error = x509ParseGeneralName(data, length, &n, &generalName);
      //Any error to report?
      if(error)
         return error;

      //Save issuer alternative name
      if(i < X509_MAX_CRL_ISSUERS)
      {
         certificateIssuer->generalNames[i] = generalName;
      }

      //Next item
      data += n;
      length -= n;
   }

   //When present, the certificate issuer CRL entry extension includes one or
   //more names (refer to RFC 5280, section 5.3.3)
   if(i == 0)
      return ERROR_INVALID_SYNTAX;

   //Save the number of issuer alternative names
   certificateIssuer->numGeneralNames = MIN(i, X509_MAX_CRL_ISSUERS);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse unknown CRL extension
 * @param[in] oid Extension identifier
 * @param[in] oidLen Length of the extension identifier
 * @param[in] critical Critical extension flag
 * @param[in] data Extension value
 * @param[in] dataLen Length of the extension value
 * @param[out] crlExtensions Information resulting from the parsing process
 * @return Error code
 **/

__weak_func error_t x509ParseUnknownCrlExtension(const uint8_t *oid,
   size_t oidLen, bool_t critical, const uint8_t *data, size_t dataLen,
   X509CrlExtensions *crlExtensions)
{
   //The extension is not supported
   return ERROR_UNSUPPORTED_EXTENSION;
}

#endif
