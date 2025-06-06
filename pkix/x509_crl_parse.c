/**
 * @file x509_crl_parse.c
 * @brief CRL (Certificate Revocation List) parsing
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
#include "pkix/x509_crl_parse.h"
#include "pkix/x509_crl_ext_parse.h"
#include "pkix/x509_sign_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Parse a CRL (Certificate Revocation List)
 * @param[in] data Pointer to the CRL to parse
 * @param[in] length Length of the CRL
 * @param[out] crlInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseCrl(const uint8_t *data, size_t length,
   X509CrlInfo *crlInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Parsing X.509 CRL...\r\n");

   //Check parameters
   if(data == NULL || crlInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the CRL information structure
   osMemset(crlInfo, 0, sizeof(X509CrlInfo));

   //The CRL is encapsulated within a sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the very first field
   data = tag.value;
   length = tag.length;

   //Parse TBSCertList structure
   error = x509ParseTbsCertList(data, length, &n, &crlInfo->tbsCertList);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SignatureAlgorithm structure
   error = x509ParseSignatureAlgo(data, length, &n, &crlInfo->signatureAlgo);
   //Any error to report?
   if(error)
      return error;

   //This field must contain the same algorithm identifier as the signature
   //field in the TBSCertList sequence (refer to RFC 5280, section 5.1.1.2)
   if(oidComp(crlInfo->signatureAlgo.oid.value,
      crlInfo->signatureAlgo.oid.length,
      crlInfo->tbsCertList.signatureAlgo.oid.value,
      crlInfo->tbsCertList.signatureAlgo.oid.length))
   {
      //Report an error
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the next field
   data += n;
   length -= n;

   //Parse SignatureValue structure
   error = x509ParseSignatureValue(data, length, &n, &crlInfo->signatureValue);
   //Any error to report?
   if(error)
      return error;

   //CRL successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse TBSCertList structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] tbsCertList Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseTbsCertList(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertList *tbsCertList)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("  Parsing TBSCertList...\r\n");

   //Read the contents of the TBSCertList structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The ASN.1 DER-encoded TBSCertList is used as the input to the
   //signature function
   tbsCertList->raw.value = data;
   tbsCertList->raw.length = tag.totalLength;

   //Point to the very first field of the TBSCertList
   data = tag.value;
   length = tag.length;

   //Parse Version field
   error = x509ParseCrlVersion(data, length, &n, &tbsCertList->version);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Signature field
   error = x509ParseSignatureAlgo(data, length, &n,
      &tbsCertList->signatureAlgo);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Issuer field
   error = x509ParseName(data, length, &n, &tbsCertList->issuer);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse ThisUpdate field
   error = x509ParseTime(data, length, &n, &tbsCertList->thisUpdate);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse NextUpdate field
   error = x509ParseTime(data, length, &n, &tbsCertList->nextUpdate);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse RevokedCertificates field
   error = x509ParseRevokedCertificates(data, length, &n, tbsCertList);
   //Any parsing error?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse CrlExtensions field
   error = x509ParseCrlExtensions(data, length, &n, &tbsCertList->crlExtensions);
   //Any parsing error?
   if(error)
      return error;

   //The CrlExtensions field is optional
   if(n > 0)
   {
      //This field must only appear if the version is 2
      if(tbsCertList->version < X509_VERSION_2)
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

error_t x509ParseCrlVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509Version *version)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing Version...\r\n");

   //The Version field is optional
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Check encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);

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

   //Parse Version field
   error = asn1ReadInt32(data, length, &tag, &value);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the version
   *version = (X509Version) value;
   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RevokedCertificates field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] tbsCertList Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRevokedCertificates(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertList *tbsCertList)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509RevokedCertificate revokedCertificate;

   //Debug message
   TRACE_DEBUG("    Parsing RevokedCertificates...\r\n");

   //No more data to process?
   if(length == 0)
   {
      //The RevokedCertificates field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //The RevokedCertificates field is encapsulated within a sequence
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Check encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);

   //The tag does not match the criteria?
   if(error)
   {
      //The RevokedCertificates field is optional
      *totalLength = 0;
      //Exit immediately
      return NO_ERROR;
   }

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   tbsCertList->revokedCerts.value = tag.value;
   tbsCertList->revokedCerts.length = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Loop through the list of revoked certificates
   while(length > 0)
   {
      //Parse current item
      error = x509ParseRevokedCertificate(data, length, &n, &revokedCertificate);
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
 * @brief Parse RevokedCertificate field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] revokedCertificate Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRevokedCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509RevokedCertificate *revokedCertificate)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing RevokedCertificate...\r\n");

   //Clear the RevokedCertificate structure
   osMemset(revokedCertificate, 0, sizeof(X509RevokedCertificate));

   //The RevokedCertificate structure shall contain a valid sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //Parse UserCertificate field
   error = x509ParseSerialNumber(data, length, &n,
      &revokedCertificate->userCert);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse RevocationDate field
   error = x509ParseTime(data, length, &n,
      &revokedCertificate->revocationDate);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse CrlEntryExtensions field
   error = x509ParseCrlEntryExtensions(data, length, &n,
      &revokedCertificate->crlEntryExtensions);
   //Any parsing error?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
}

#endif
