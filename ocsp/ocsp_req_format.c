/**
 * @file ocsp_req_format.c
 * @brief OCSP request formatting
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
#define TRACE_LEVEL OCSP_TRACE_LEVEL

//Dependencies
#include "ocsp/ocsp_req_format.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (OCSP_SUPPORT == ENABLED)


/**
 * @brief Format OCSPRequest structure
 * @param[in] request Pointer to the OCSPRequest structure
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatRequest(const OcspRequest *request, uint8_t *output,
   size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Format TBSRequest structure
   error = ocspFormatTbsRequest(&request->tbsRequest, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The OCSPRequest structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = n;
   tag.value = output;

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
 * @brief Format TBSRequest structure
 * @param[in] tbsRequest Pointer to the TBSRequest structure
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatTbsRequest(const OcspTbsRequest *tbsRequest, uint8_t *output,
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

   //Format Version field
   error = ocspFormatVersion(tbsRequest->version, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format RequestList structure
   error = ocspFormatRequestList(tbsRequest->requestList,
      tbsRequest->numRequests, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format RequestExtensions structure
   error = ocspFormatRequestExtensions(&tbsRequest->requestExtensions, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The TBSRequest structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

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
 * @brief Format Version field
 * @param[in] version Version number
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatVersion(OcspVersion version, uint8_t *output,
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
   tag.value = output;

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
 * @brief Format RequestList structure
 * @param[in] requestList List of requests
 * @param[in] numRequests Number of requests in the list
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatRequestList(const OcspSingleRequest *requestList,
   uint_t numRequests, uint8_t *output, size_t *written)
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

   //The RequestList structure contains one or more single certificate status
   //requests
   for(i = 0; i < numRequests; i++)
   {
      //Format Request structure
      error = ocspFormatSingleRequest(&requestList[i], p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      length += n;
   }

   //The RequestList structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

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
 * @brief Format Request structure
 * @param[in] singleRequest Pointer to the Request structure
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatSingleRequest(const OcspSingleRequest *singleRequest,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Format CertID structure
   error = ocspFormatCertId(&singleRequest->reqCert, output, &n);
   //Any error to report?
   if(error)
      return error;

   //The CertID structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = n;
   tag.value = output;

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
 * @brief Format CertID structure
 * @param[in] certId Pointer to the CertID structure
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatCertId(const OcspCertId *certId, uint8_t *output,
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

   //The HashAlgorithm field specifies the hash algorithm used to generate the
   //issuerNameHash and issuerKeyHash values
   error = ocspFormatHashAlgo(certId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format IssuerNameHash field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = certId->issuerNameHash.length;
   tag.value = certId->issuerNameHash.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Format IssuerKeyHash field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = certId->issuerKeyHash.length;
   tag.value = certId->issuerKeyHash.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The SerialNumber field is the serial number of the certificate for which
   //status is being requested
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = certId->serialNumber.length;
   tag.value = certId->serialNumber.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The CertID structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

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
 * @brief Format HashAlgorithm structure
 * @param[in] certId Pointer to the CertID structure
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatHashAlgo(const OcspCertId *certId, uint8_t *output,
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

   //Format hash algorithm OID
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = certId->hashAlgo.length;
   tag.value = certId->hashAlgo.value;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //The Params field is optional (refer to RFC 5912, section 2)
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_NULL;
   tag.length = 0;
   tag.value = NULL;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, p, &n);

   //The AlgorithmIdentifier structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = output;

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
 * @brief Format RequestExtensions structure
 * @param[in] extensions Pointer to the RequestExtensions structure
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatRequestExtensions(const OcspExtensions *extensions,
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

   //The Nonce extension is used to cryptographically binds a request and a
   //response to prevent replay attacks (refer to RFC 8954, section 2.1)
   error = ocspFormatNonceExtension(&extensions->nonce, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   p += n;
   length += n;

   //Any extensions written?
   if(length > 0)
   {
      //The extensions are encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Explicit tagging shall be used to encode the Extensions structure
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 2;
      tag.length = n;
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Nonce extension
 * @param[in] nonce Pointer to the Nonce extension
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspFormatNonceExtension(const X509OctetString *nonce, uint8_t *output,
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

   //Valid nonce?
   if(nonce->value != NULL && nonce->length > 0)
   {
      //Format the extension identifier
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = sizeof(PKIX_OCSP_NONCE_OID);
      tag.value = PKIX_OCSP_NONCE_OID;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      p += n;
      length += n;

      //Format the Nonce field
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OCTET_STRING;
      tag.length = nonce->length;
      tag.value = nonce->value;

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
      tag.value = p;

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
      tag.value = output;

      //Write the corresponding ASN.1 tag
      error = asn1WriteTag(&tag, FALSE, output, &length);
      //Any error to report?
      if(error)
         return error;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
}

#endif
