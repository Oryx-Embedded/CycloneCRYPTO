/**
 * @file ocsp_resp_parse.c
 * @brief OCSP response parsing
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
#include "ocsp/ocsp_resp_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_ext_parse.h"
#include "pkix/x509_sign_parse.h"
#include "debug.h"

//Check crypto library configuration
#if (OCSP_SUPPORT == ENABLED)


/**
 * @brief Parse OCSPResponse structure
 * @param[in] data Pointer to the X.509 certificate to parse
 * @param[in] length Length of the X.509 certificate
 * @param[out] response Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseResponse(const uint8_t *data, size_t length,
   OcspResponse *response)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Check parameters
   if(data == NULL || response == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("OCSP response (%" PRIuSIZE " bytes):\r\n", length);
   //Dump OCSP response
   asn1DumpObject(data, length, 0);

   //Clear the OCSP response structure
   osMemset(response, 0, sizeof(OcspResponse));

   //Raw contents of the OCSPResponse structure
   response->raw.value = data;
   response->raw.length = length;

   //The OCSPResponse structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //An OCSP response at a minimum consists of a ResponseStatus field
   //indicating the processing status of the prior request (refer to
   //RFC 6960, section 4.2.1)
   error = ocspParseResponseStatus(data, length, &n,
      &response->responseStatus);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Check response status
   if(response->responseStatus == OCSP_RESP_STATUS_SUCCESSFUL)
   {
      //An OCSP response consists of a response type and the bytes of the
      //actual response
      error = ocspParseResponseBytes(data, length, response);
   }
   else
   {
      //If the value of ResponseStatus is one of the error conditions, the
      //ResponseBytes field is not set
   }

   //Return status code
   return error;
}


/**
 * @brief Parse ResponseStatus field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] status OCSP response status
 * @return Error code
 **/

error_t ocspParseResponseStatus(const uint8_t *data, size_t length,
   size_t *totalLength, OcspResponseStatus *status)
{
   error_t error;
   Asn1Tag tag;

   //Read ASN.1 tag
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

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The response status indicates the processing status of the request
   *status = (OcspResponseStatus) tag.value[0];

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ResponseBytes structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] response Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseResponseBytes(const uint8_t *data, size_t length,
   OcspResponse *response)
{
   error_t error;
   Asn1Tag tag;

   //Explicit tagging shall be used to encode the ResponseBytes structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
   //Invalid tag?
   if(error)
      return error;

   //Read the inner sequence
   error = asn1ReadSequence(tag.value, tag.length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read ResponseType field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the OID
   response->responseType.value = tag.value;
   response->responseType.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Response field
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first byte of the actual response
   data = tag.value;
   length = tag.length;

   //OCSP clients shall be capable of receiving and processing responses of
   //the id-pkix-ocsp-basic response type (refer to RFC 6960, section 4.2.1)
   if(OID_COMP(response->responseType.value, response->responseType.length,
      PKIX_OCSP_BASIC_OID) == 0)
   {
      //The value for response shall be the DER encoding of BasicOCSPResponse
      error = ocspParseBasicResponse(data, length,
         &response->basicResponse);
   }
   else
   {
      //Unknown response type
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse BasicOCSPResponse structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] basicResponse Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseBasicResponse(const uint8_t *data, size_t length,
   OcspBasicResponse *basicResponse)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("OCSP basic response (%" PRIuSIZE " bytes):\r\n", length);
   //Dump OCSP response
   asn1DumpObject(data, length, 0);

   //The BasicOCSPResponse structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Parse TbsResponseData structure
   error = ocspParseTbsResponseData(data, length, &n,
      &basicResponse->tbsResponseData);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse SignatureAlgorithm structure
   error = x509ParseSignatureAlgo(data, length, &n,
      &basicResponse->signatureAlgo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse Signature structure
   error = x509ParseSignatureValue(data, length, &n,
      &basicResponse->signature);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The responder may include certificates in the Certs field of
   //BasicOCSPResponse that help the OCSP client verify the responder's
   //signature (refer to RFC 6960, section 4.2.1)
   if(length > 0)
   {
      //Parse ASN.1 tag
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);

      //Check whether the Certs field is present
      if(!error)
      {
         //Parse Certs field
         error = ocspParseCerts(tag.value, tag.length, &basicResponse->certs);
         //Any error to report?
         if(error)
            return error;
      }
   }
   else
   {
      //If no certificates are included, then Certs should be absent
   }

   //Certificate successfully parsed
   return NO_ERROR;
}


/**
 * @brief Parse TbsResponseData structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] tbsResponseData Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseTbsResponseData(const uint8_t *data, size_t length,
   size_t *totalLength, OcspTbsResponseData *tbsResponseData)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The TbsResponseData structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //The ASN.1 DER-encoded TbsResponseData is used as the input to the
   //signature function
   tbsResponseData->raw.value = data;
   tbsResponseData->raw.length = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //The Version field contains the version of the response syntax
   error = ocspParseVersion(data, length, &n, &tbsResponseData->version);
   //Any error to report?
   if(error)
      return error;

   //The version must be v1 for this version of the basic response syntax (refer
   //to RFC 6960, section 4.2.2.3)
   if(tbsResponseData->version != OCSP_VERSION_1)
      return ERROR_INVALID_VERSION;

   //Point to the next field
   data += n;
   length -= n;

   //The ResponderID field contains either the name of the responder or a hash
   //of the responder's public key
   error = ocspParseResponderId(data, length, &n,
      &tbsResponseData->responderId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The ProducedAt field indicated the time at which the response was generated
   error = x509ParseTime(data, length, &n, &tbsResponseData->producedAt);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The basic response contains responses for each of the certificates in a
   //request
   error = ocspParseResponses(data, length, &n, tbsResponseData);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The TbsResponseData structure may contain an optional field
   if(length > 0)
   {
      //Parse ASN.1 tag
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 1);

      //Check whether the ResponseExtensions field is present
      if(!error)
      {
         //OCSP extensions are based on the extension model employed in X.509
         //version 3 certificates (refer to RFC 6960, section 4.4)
         error = ocspParseResponseExtensions(tag.value, tag.length,
            &tbsResponseData->responseExtensions);
         //Any error to report?
         if(error)
            return error;
      }
   }

   //Successful processing
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

error_t ocspParseVersion(const uint8_t *data, size_t length,
   size_t *totalLength, OcspVersion *version)
{
   error_t error;
   int32_t value;
   Asn1Tag tag;

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
      //Assume OCSP version 1
      *version = OCSP_VERSION_1;
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

   //Save certificate version
   *version = (OcspVersion) value;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ResponderID structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] responderId Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseResponderId(const uint8_t *data, size_t length,
   size_t *totalLength, OcspResponderId *responderId)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Explicit tagging shall be used to encode the responder ID
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   if(!tag.constructed || tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
      return ERROR_INVALID_TAG;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the inner value
   data = tag.value;
   length = tag.length;

   //The ResponderID field contains either the name of the responder or
   //a hash of the responder's public key
   if(tag.objType == 1)
   {
      //Retrieve the name of the responder
      error = x509ParseName(data, length, &n, &responderId->name);
   }
   else if(tag.objType == 2)
   {
      //Retrieve the hash of the responder's public key
      error = asn1ReadOctetString(data, length, &tag);

      //Check status code
      if(!error)
      {
         responderId->keyHash.value = tag.value;
         responderId->keyHash.length = tag.length;
      }
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
 * @brief Parse Responses structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] tbsResponseData Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseResponses(const uint8_t *data, size_t length,
   size_t *totalLength, OcspTbsResponseData *tbsResponseData)
{
   error_t error;
   uint_t i;
   size_t n;
   Asn1Tag tag;

   //The Responses structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //The basic response contains responses for each of the certificates in a
   //request
   for(i = 0; i < OCSP_MAX_RESPONSES && length > 0; i++)
   {
      //Parse current response
      error = ocspParseSingleResponse(data, length, &n,
         &tbsResponseData->responses[i]);
      //Any error to report?
      if(error)
         return error;

      //Point to the next response
      data += n;
      length -= n;
   }

   //Save the number of responses
   tbsResponseData->numResponses = i;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SingleResponse structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] singleResponse Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseSingleResponse(const uint8_t *data, size_t length,
   size_t *totalLength, OcspSingleResponse *singleResponse)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The SingleResponse structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //The CertID field contains an  identifier of the certificate for which
   //revocation status information is being provided
   error = ocspParseCertId(data, length, &n, &singleResponse->certId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The CertStatus field contains the revocation status of the certificate
   //(good, revoked, or unknown)
   error = ocspParseCertStatus(data, length, &n, singleResponse);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The ThisUpdate field indicates the most recent time at which the status
   //being indicated is known by the responder to have been correct
   error = x509ParseTime(data, length, &n, &singleResponse->thisUpdate);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The SingleResponse structure may contain optional fields
   if(length > 0)
   {
      //Parse ASN.1 tag
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);

      //Check whether the NextUpdate field is present
      if(!error)
      {
         //The NextUpdate field indicates the time at or before which newer
         //information will be available about the status of the certificate
         error = x509ParseTime(tag.value, tag.length, &n,
            &singleResponse->nextUpdate);
         //Any error to report?
         if(error)
            return error;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;
      }
   }

   //The SingleResponse structure may contain optional fields
   if(length > 0)
   {
      //Parse ASN.1 tag
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 1);

      //Check whether the SingleExtensions field is present
      if(!error)
      {
         //OCSP extensions are based on the extension model employed in X.509
         //version 3 certificates (refer to RFC 6960, section 4.4)
         error = ocspParseSingleExtensions(tag.value, tag.length,
            &singleResponse->singleExtensions);
         //Any error to report?
         if(error)
            return error;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CertID structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certId Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseCertId(const uint8_t *data, size_t length,
   size_t *totalLength, OcspCertId *certId)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The CertID structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Parse HashAlgorithm structure
   error = ocspParseHashAlgo(data, length, &n, certId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //Parse IssuerNameHash field
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the hash of the issuer's distinguished name (DN)
   certId->issuerNameHash.value = tag.value;
   certId->issuerNameHash.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse IssuerKeyHash field
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the hash of the issuer's public key
   certId->issuerKeyHash.value = tag.value;
   certId->issuerKeyHash.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Parse SerialNumber field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save serial number
   certId->serialNumber.value = tag.value;
   certId->serialNumber.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HashAlgorithm structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] certId Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseHashAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, OcspCertId *certId)
{
   error_t error;
   Asn1Tag tag;

   //The HashAlgorithm structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Parse hash algorithm OID
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save hash algorithm OID
   certId->hashAlgo.value = tag.value;
   certId->hashAlgo.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CertStatus structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] singleResponse Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseCertStatus(const uint8_t *data, size_t length,
   size_t *totalLength, OcspSingleResponse *singleResponse)
{
   error_t error;
   Asn1Tag tag;

   //Implicit tagging shall be used to encode the certificate status
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
      return ERROR_INVALID_TAG;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Check certificate status value
   if(tag.objType == 0)
   {
      //The "good" state indicates a positive response to the status inquiry
      singleResponse->certStatus = OCSP_CERT_STATUS_GOOD;
   }
   else if(tag.objType == 1 && tag.constructed)
   {
      //The "revoked" state indicates that the certificate has been revoked,
      //either temporarily (the revocation reason is certificateHold) or
      //permanently
      singleResponse->certStatus = OCSP_CERT_STATUS_REVOKED;

      //Parse RevokedInfo structure
      error = ocspParseRevokedInfo(tag.value, tag.length,
         &singleResponse->revokedInfo);
   }
   else if(tag.objType == 2)
   {
      //The "unknown" state indicates that the responder doesn't know about
      //the certificate being requested, usually because the request indicates
      //an unrecognized issuer that is not served by this responder
      singleResponse->certStatus = OCSP_CERT_STATUS_UNKNOWN;
   }
   else
   {
      //Invalid status
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse RevokedInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] revokedInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseRevokedInfo(const uint8_t *data, size_t length,
   OcspRevokedInfo *revokedInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //The RevocationTime field indicates the time at which the certificate was
   //revoked or placed on hold
   error = x509ParseTime(data, length, &n, &revokedInfo->revocationTime);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The RevokedInfo structure may contain an optional field
   if(length > 0)
   {
      //Parse ASN.1 tag
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);

      //Check whether the RevocationReason field is present
      if(!error)
      {
         //Parse RevocationReason field indicates the reason why the certificate
         //was revoked
         error = ocspParseRevocationReason(tag.value, tag.length,
            &revokedInfo->revocationReason);
         //Any error to report?
         if(error)
            return error;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RevocationReason field
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] revocationReason Reason why the certificate was revoked
 * @return Error code
 **/

error_t ocspParseRevocationReason(const uint8_t *data, size_t length,
   X509CrlReasons *revocationReason)
{
   error_t error;
   Asn1Tag tag;

   //Read ASN.1 tag
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

   //Parse RevocationReason field indicates the reason why the certificate
   //was revoked
   *revocationReason = (X509CrlReasons) tag.value[0];

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Certs structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] certs Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseCerts(const uint8_t *data, size_t length,
   OcspCerts *certs)
{
   error_t error;
   Asn1Tag tag;

   //The HashAlgorithm structure is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   certs->raw.value = tag.value;
   certs->raw.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ResponseExtensions structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] responseExtensions Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseResponseExtensions(const uint8_t *data, size_t length,
   OcspExtensions *responseExtensions)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //This field is a sequence of one or more OCSP extensions
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   responseExtensions->raw.value = tag.value;
   responseExtensions->raw.length = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //OCSP extension are based on the extension model employed in X.509 version 3
   //certificates (refer to RFC 6960, section 4.4)
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
         PKIX_OCSP_NONCE_OID) == 0)
      {
         //Parse Nonce extension
         error = ocspParseNonceExtension(extension.critical,
            extension.data.value, extension.data.length,
            &responseExtensions->nonce);
      }
      else
      {
         //Unrecognized extensions must be ignored, unless they have the
         //critical flag set and are not understood refer to RFC 6960,
         //section 4.1.2)
         if(extension.critical)
         {
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
 * @brief Parse SingleExtensions structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] singleExtensions Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseSingleExtensions(const uint8_t *data, size_t length,
   OcspSingleExtensions *singleExtensions)
{
   error_t error;
   size_t n;
   Asn1Tag tag;
   X509Extension extension;

   //This field is a sequence of one or more OCSP extensions
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Raw contents of the ASN.1 sequence
   singleExtensions->raw.value = tag.value;
   singleExtensions->raw.length = tag.length;

   //Point to the first item of the sequence
   data = tag.value;
   length = tag.length;

   //OCSP extension are based on the extension model employed in X.509 version 3
   //certificates (refer to RFC 6960, section 4.4)
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

      //Unrecognized extensions must be ignored, unless they have the critical
      //flag set and are not understood refer to RFC 6960, section 4.1.2)
      if(extension.critical)
      {
         return ERROR_UNSUPPORTED_EXTENSION;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Nonce extension
 * @param[in] critical Critical extension flag
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] nonce Information resulting from the parsing process
 * @return Error code
 **/

error_t ocspParseNonceExtension(bool_t critical, const uint8_t *data,
   size_t length, X509OctetString *nonce)
{
   error_t error;
   Asn1Tag tag;

   //The Nonce extension is used to cryptographically binds a request and
   //a response to prevent replay attacks (refer to RFC 8954, section 2.1)
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the nonce
   nonce->value = tag.value;
   nonce->length = tag.length;

   //Successful processing
   return NO_ERROR;
}

#endif
