/**
 * @file scep_client_resp_parse.c
 * @brief SCEP response parsing
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
#define TRACE_LEVEL SCEP_TRACE_LEVEL

//Dependencies
#include "scep/scep_client.h"
#include "scep/scep_client_resp_parse.h"
#include "scep/scep_client_misc.h"
#include "scep/scep_debug.h"
#include "pkcs7/pkcs7_parse.h"
#include "pkcs7/pkcs7_decrypt.h"
#include "pkcs7/pkcs7_sign_verify.h"
#include "pkix/x509_cert_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "str.h"
#include "debug.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Parse GetCACaps response
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientParseGetCaCapsResponse(ScepClientContext *context)
{
   char_t *p;
   char_t *token;
   char_t *keyword;

   //A client that receives an empty message or an HTTP error should interpret
   //the response as if none of the capabilities listed are supported by the CA
   //(refer to RFC 8894, section 3.5.2)
   context->caCaps = SCEP_CA_CAPS_NONE;

   //Check HTTP status code
   if(HTTP_STATUS_CODE_2YZ(context->statusCode))
   {
      //Check whether the body of the response is truncated
      if(context->bufferLen >= SCEP_CLIENT_BUFFER_SIZE)
         return ERROR_RESPONSE_TOO_LARGE;

      //Properly terminate the body with a NULL character
      context->buffer[context->bufferLen] = '\0';

      //The response for a GetCACaps message is a list of CA capabilities
      token = osStrtok_r((char_t *) context->buffer, "\n", &p);

      //Parse the list of keywords
      while(token != NULL)
      {
         //Clients must accept the standard HTTP-style text delimited by
         //<CR><LF> as well as the text delimited by <LF>
         keyword = strTrimWhitespace(token);

         //Clients should ignore the text case when processing the message
         if(osStrcasecmp(keyword, "AES") == 0)
         {
            //CA supports the AES128-CBC encryption algorithm
            context->caCaps |= SCEP_CA_CAPS_AES;
         }
         else if(osStrcasecmp(keyword, "DES3") == 0)
         {
            //CA supports the triple DES-CBC encryption algorithm
            context->caCaps |= SCEP_CA_CAPS_DES3;
         }
         else if(osStrcasecmp(keyword, "GetNextCACert") == 0)
         {
            //CA supports the GetNextCACert message
            context->caCaps |= SCEP_CA_CAPS_GET_NEXT_CA_CERT;
         }
         else if(osStrcasecmp(keyword, "POSTPKIOperation") == 0)
         {
            //CA supports PKIOPeration messages sent via HTTP POST
            context->caCaps |= SCEP_CA_CAPS_POST_PKI_OPERATION;
         }
         else if(osStrcasecmp(keyword, "Renewal") == 0)
         {
            //CA supports the Renewal CA operation
            context->caCaps |= SCEP_CA_CAPS_RENEWAL;
         }
         else if(osStrcasecmp(keyword, "SHA-1") == 0)
         {
            //CA supports the SHA-1 hashing algorithm
            context->caCaps |= SCEP_CA_CAPS_SHA1;
         }
         else if(osStrcasecmp(keyword, "SHA-256") == 0)
         {
            //CA supports the SHA-256 hashing algorithm
            context->caCaps |= SCEP_CA_CAPS_SHA256;
         }
         else if(osStrcasecmp(keyword, "SHA-512") == 0)
         {
            //CA supports the SHA-512 hashing algorithm
            context->caCaps |= SCEP_CA_CAPS_SHA512;
         }
         else if(osStrcasecmp(keyword, "SCEPStandard") == 0)
         {
            //CA supports all mandatory-to-implement sections of the SCEP
            //standard. This keyword implies "AES", "POSTPKIOperation", and
            //"SHA-256"
            context->caCaps |= SCEP_CA_CAPS_AES | SCEP_CA_CAPS_POST_PKI_OPERATION |
               SCEP_CA_CAPS_SHA256;
         }
         else
         {
            //A client must be able to accept and ignore any unknown keywords
            //that might be sent by a CA (refer to RFC 8894, section 3.5.2)
         }

         //Get the next keyword
         token = osStrtok_r(NULL, "\n", &p);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse GetCACert response
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientParseGetCaCertResponse(ScepClientContext *context)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Clear CA certificate first
   context->caCertLen = 0;

   //Check HTTP status code
   if(HTTP_STATUS_CODE_2YZ(context->statusCode))
   {
      //The response for GetCACert is different between the case where the CA
      //directly communicates with the client during the enrolment and the case
      //where an intermediate CA exists and the client communicates with this
      //CA during the enrolment (refer to RFC 8894, section 4.2.1)
      if(osStrcmp(context->contentType, "application/x-x509-ca-cert") == 0)
      {
         //Check the length of the CA certificate
         if(context->bufferLen > 0 &&
            context->bufferLen <= SCEP_CLIENT_MAX_CA_CERT_LEN)
         {
            //If the CA does not have any intermediate CA certificates, the
            //response consists of a single X.509 CA certificate
            osMemcpy(context->caCert, context->buffer, context->bufferLen);
            context->caCertLen = context->bufferLen;
         }
         else
         {
            //Report an error
            error = ERROR_RESPONSE_TOO_LARGE;
         }
      }
      else if(osStrcmp(context->contentType, "application/x-x509-ca-ra-cert") == 0)
      {
         size_t n;
         Pkcs7ContentInfo contentInfo;
         Pkcs7SignedData signedData;

         //If the CA has intermediate CA certificates, the response consists of
         //a degenerate certificates-only CMS SignedData message containing the
         //certificates, with the intermediate CA certificate(s) as the leaf
         //certificate(s)
         error = pkcs7ParseContentInfo(context->buffer, context->bufferLen, &n,
            &contentInfo);

         //Check status code
         if(!error)
         {
            //Parse signed-data content
            error = pkcs7ParseSignedData(contentInfo.content.value,
               contentInfo.content.length, &signedData);
         }

         //Check status code
         if(!error)
         {
            //Check the length of the certificate chain
            if(signedData.certificates.raw.length > 0 &&
               signedData.certificates.raw.length <= SCEP_CLIENT_MAX_CA_CERT_LEN)
            {
               //Save the CA certificate chain
               osMemcpy(context->caCert, signedData.certificates.raw.value,
                  signedData.certificates.raw.length);

               //Save the length of the CA certificate chain
               context->caCertLen = signedData.certificates.raw.length;
            }
            else
            {
               //Report an error
               error = ERROR_RESPONSE_TOO_LARGE;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_RESPONSE;
      }
   }
   else
   {
      //Report an error
      error = ERROR_UNEXPECTED_STATUS;
   }

   //Check status code
   if(!error)
   {
      //After the client gets the CA certificate, it should authenticate it
      //(refer to RFC 8894, section 2.2)
      error = scepClientVerifyCaCert(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse CertRep response
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientParseCertResponse(ScepClientContext *context)
{
   error_t error;

   //Check HTTP status code
   if(HTTP_STATUS_CODE_2YZ(context->statusCode))
   {
      //The response will have a Content-Type of "application/x-pki-message"
      //(refer to RFC 8894, section 4.3.1)
      if(osStrcmp(context->contentType, "application/x-pki-message") == 0)
      {
         //The basic building block of all secured SCEP messages is the SCEP
         //pkiMessage (refer to RFC 8894, section 3.2)
         error = scepClientParsePkiMessage(context, context->buffer,
            context->bufferLen);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_RESPONSE;
      }
   }
   else
   {
      //The text content type is used for message content that is primarily in
      //human-readable text character format
      if(osStrncmp(context->contentType, "text/", 5) == 0)
      {
         //Properly terminate the string with a NULL character
         context->buffer[context->bufferLen] = '\0';
         //Dump HTTP response body
         TRACE_DEBUG("%s", context->buffer);
      }

      //Report an error
      error = ERROR_UNEXPECTED_STATUS;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse PKI message
 * @param[in] context Pointer to the SCEP client context
 * @param[in] data Pointer to the PKI message to parse
 * @param[in] length Length of the PKI message
 * @return Error code
 **/

error_t scepClientParsePkiMessage(ScepClientContext *context,
   const uint8_t *data, size_t length)
{
   error_t error;
   size_t n;
   uint_t messageType;
   uint_t pkiStatus;
   Pkcs7ContentInfo contentInfo;
   Pkcs7SignedData signedData;
   Pkcs7SignerInfo signerInfo;
   Pkcs7Attribute attribute;
   X509CertInfo *certInfo;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("pkiMessage (%" PRIuSIZE " bytes):\r\n", length);
   asn1DumpObject(data, length, 0);

   //The general syntax for content exchanged between entities associates a
   //content type with content (refer to RFC 2315, section 7)
   error = pkcs7ParseContentInfo(data, length, &n, &contentInfo);
   //Any error to report?
   if(error)
      return error;

   //The basic building block of all secured SCEP messages is the SCEP
   //pkiMessage. It consists of a CMS SignedData content type (refer to
   //RFC 8894, section 3.2)
   if(OID_COMP(contentInfo.contentType.value, contentInfo.contentType.length,
      PKCS7_SIGNED_DATA_OID) != 0)
   {
      return ERROR_INVALID_TYPE;
   }

   //Parse signed-data content
   error = pkcs7ParseSignedData(contentInfo.content.value,
      contentInfo.content.length, &signedData);
   //Any error to report?
   if(error)
      return error;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = cryptoAllocMem(sizeof(X509CertInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //The recipient may obtain the correct public key for the signer by any
      //means, but the preferred method is from a certificate obtained from the
      //SignedData certificates field
      error = scepClientParseCaCert(context, certInfo);

      //Check status code
      if(!error)
      {
         //Search a list of per-signer informations for a matching signer
         error = pkcs7FindSigner(&signedData.signerInfos, certInfo,
            &signerInfo);
      }

      //Check status code
      if(!error)
      {
         //Verify signature over signed-data content
         error = pkcs7VerifySignedData(&signedData, &signerInfo, certInfo);
      }

      //Release previously allocated memory
      cryptoFreeMem(certInfo);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Any error to report?
   if(error)
      return error;

   //All messages must contain a transactionID attribute
   error = pkcs7FindAttribute(signerInfo.authenticatedAttributes.raw.value,
      signerInfo.authenticatedAttributes.raw.length, SCEP_TRANSACTION_ID_OID,
      sizeof(SCEP_TRANSACTION_ID_OID), &attribute);
   //Any error to report?
   if(error)
      return error;

   //The attribute is encoded as PrintableString
   if(attribute.type != ASN1_TYPE_PRINTABLE_STRING)
      return ERROR_INVALID_SYNTAX;

   //The transactionID must be used for all PKI messages exchanged for a given
   //operation
   if(attribute.data.length != osStrlen(context->transactionId) ||
      osMemcmp(attribute.data.value, context->transactionId,
      attribute.data.length) != 0)
   {
      return ERROR_INVALID_SYNTAX;
   }

   //The messageType attribute specifies the type of operation performed by the
   //transaction. This attribute must be included in all PKI messages (refer to
   //RFC 8894, section 3.2.1.2)
   error = pkcs7FindAttribute(signerInfo.authenticatedAttributes.raw.value,
      signerInfo.authenticatedAttributes.raw.length, SCEP_MESSAGE_TYPE_OID,
      sizeof(SCEP_MESSAGE_TYPE_OID), &attribute);
   //Any error to report?
   if(error)
      return error;

   //The attribute is encoded as a PrintableString
   if(attribute.type != ASN1_TYPE_PRINTABLE_STRING)
      return ERROR_INVALID_SYNTAX;

   //The attribute value is a numeric text string
   error = x509ParseInt(attribute.data.value, attribute.data.length,
      &messageType);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   scepDumpMessageType(messageType);

   //The recipient must copy the senderNonce into the recipientNonce of the
   //reply as a proof of liveliness
   error = pkcs7FindAttribute(signerInfo.authenticatedAttributes.raw.value,
      signerInfo.authenticatedAttributes.raw.length, SCEP_RECIPIENT_NONCE_OID,
      sizeof(SCEP_RECIPIENT_NONCE_OID), &attribute);
   //Any error to report?
   if(error)
      return error;

   //The nonce must be a 16-byte binary data string
   if(attribute.data.length != SCEP_NONCE_SIZE)
      return ERROR_BAD_NONCE;

   //The original sender must verify that the recipientNonce of the reply
   //matches the senderNonce it sent in the request. If the nonce does not
   //match, then the message must be rejected (refer to RFC 8894,
   //section 3.2.1.5)
   if(osMemcmp(attribute.data.value, context->senderNonce, SCEP_NONCE_SIZE) != 0)
      return ERROR_BAD_NONCE;

   //All response messages must include transaction status information, which
   //is defined as a pkiStatus attribute (refer to RFC 8894, section 3.2.1.3)
   error = pkcs7FindAttribute(signerInfo.authenticatedAttributes.raw.value,
      signerInfo.authenticatedAttributes.raw.length, SCEP_PKI_STATUS_OID,
      sizeof(SCEP_PKI_STATUS_OID), &attribute);
   //Any error to report?
   if(error)
      return error;

   //The attribute is encoded as a PrintableString
   if(attribute.type != ASN1_TYPE_PRINTABLE_STRING)
      return ERROR_INVALID_SYNTAX;

   //The attribute value is a numeric text string
   error = x509ParseInt(attribute.data.value, attribute.data.length,
      &pkiStatus);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   scepDumpPkiStatus(pkiStatus);

   //Check PKI status
   if(pkiStatus == SCEP_PKI_STATUS_SUCCESS)
   {
      //The data content type is just an octet string (refer to RFC 2315,
      //section 8)
      error = asn1ReadOctetString(signedData.contentInfo.content.value,
         signedData.contentInfo.content.length, &tag);
      //Any error to report?
      if(error)
         return error;

      //When the pkiStatus attribute is set to SUCCESS, the messageData for
      //this message consists of a degenerate certificates-only CMS SignedData
      //message
      error = scepClientParsePkcsPkiEnvelope(context, messageType, tag.value,
         tag.length);
      //Any error to report?
      if(error)
         return error;
   }
   else if(pkiStatus == SCEP_PKI_STATUS_FAILURE)
   {
      //When the pkiStatus attribute is set to FAILURE, the reply must also
      //contain a failInfo attribute set to the appropriate error condition
      //describing the failure (refer to RFC 8894, section 3.3.2.2)
      error = pkcs7FindAttribute(signerInfo.authenticatedAttributes.raw.value,
         signerInfo.authenticatedAttributes.raw.length, SCEP_FAIL_INFO_OID,
         sizeof(SCEP_FAIL_INFO_OID), &attribute);
      //Any error to report?
      if(error)
         return error;

      //The attribute is encoded as a PrintableString
      if(attribute.type != ASN1_TYPE_PRINTABLE_STRING)
         return ERROR_INVALID_SYNTAX;

      //The attribute value is a numeric text string
      error = x509ParseInt(attribute.data.value, attribute.data.length,
         &context->failInfo);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      scepDumpFailInfo(context->failInfo);

      //The request is rejected
      return ERROR_REQUEST_REJECTED;
   }
   else if(pkiStatus == SCEP_PKI_STATUS_PENDING)
   {
      //The Request pending for manual approval (refer to RFC 8894, section
      //3.2.1.3)
      return ERROR_REQUEST_PENDING;
   }
   else
   {
      //PKI status values not defined above must be treated as errors unless
      //their use has been negotiated through GetCACaps (refer to RFC 8894,
      //section 3.2.1.3)
      return ERROR_INVALID_SYNTAX;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse pkcsPKIEnvelope structure
 * @param[in] context Pointer to the SCEP client context
 * @param[in] messageType SCEP message type
 * @param[in] data Pointer to the pkcsPKIEnvelope structure to parse
 * @param[in] length Length of the pkcsPKIEnvelope structure
 * @return Error code
 **/

error_t scepClientParsePkcsPkiEnvelope(ScepClientContext *context,
   uint_t messageType, const uint8_t *data, size_t length)
{
   error_t error;
   size_t n;
   Pkcs7ContentInfo contentInfo;
   Pkcs7EnvelopedData envelopedData;
   X509CertInfo *certInfo;

   //Debug message
   TRACE_DEBUG("pkcsPKIEnvelope (%" PRIuSIZE " bytes):\r\n", length);
   asn1DumpObject(data, length, 0);

   //The general syntax for content exchanged between entities associates a
   //content type with content (refer to RFC 2315, section 7)
   error = pkcs7ParseContentInfo(data, length, &n, &contentInfo);
   //Any error to report?
   if(error)
      return error;

   //The information portion of a SCEP message is carried inside an
   //EnvelopedData content type (refer to RFC 8894, section 3.2.2)
   if(OID_COMP(contentInfo.contentType.value, contentInfo.contentType.length,
      PKCS7_ENVELOPED_DATA_OID) != 0)
   {
      return ERROR_INVALID_TYPE;
   }

   //Parse enveloped-data content
   error = pkcs7ParseEnvelopedData(contentInfo.content.value,
      contentInfo.content.length, &envelopedData);
   //Any error to report?
   if(error)
      return error;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = cryptoAllocMem(sizeof(X509CertInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //If the key being certified allows encryption, then the CA's CertResp
      //will use the same certificate's public key when encrypting the response
      //(refer to RFC 8894, section 2.3)
      error = x509ParseCertificate(context->cert, context->certLen, certInfo);

      //Check status code
      if(!error)
      {
         //Decrypt enveloped-data content
         error = pkcs7DecryptEnvelopedData(&envelopedData, certInfo,
            &context->rsaPrivateKey, context->buffer, &n);
      }

      //Release previously allocated memory
      cryptoFreeMem(certInfo);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Any error to report?
   if(error)
      return error;

   //When a particular SCEP message carries data, this data is carried in the
   //messageData (refer to RFC 8894, section 3)
   return scepClientParseMessageData(context, messageType, context->buffer, n);
}


/**
 * @brief Parse messageData
 * @param[in] context Pointer to the SCEP client context
 * @param[in] messageType SCEP message type
 * @param[in] data Pointer to the pkcsPKIEnvelope structure to parse
 * @param[in] length Length of the pkcsPKIEnvelope structure
 * @return Error code
 **/

error_t scepClientParseMessageData(ScepClientContext *context,
   uint_t messageType, const uint8_t *data, size_t length)
{
   error_t error;
   size_t n;
   Pkcs7ContentInfo contentInfo;
   Pkcs7SignedData signedData;
   Asn1Tag tag;

   //The CertRep is the response to certificate or CRL request
   if(messageType != SCEP_MSG_TYPE_CERT_REP)
      return ERROR_INVALID_TYPE;

   //Debug message
   TRACE_DEBUG("messageData (%" PRIuSIZE " bytes):\r\n", length);
   asn1DumpObject(data, length, 0);

   //The general syntax for content exchanged between entities associates a
   //content type with content (refer to RFC 2315, section 7)
   error = pkcs7ParseContentInfo(data, length, &n, &contentInfo);
   //Any error to report?
   if(error)
      return error;

   //The messageData for this type consists of a degenerate certificates-only CMS
   //SignedData message (refer to RFC 8894, section 3.3.2)
   if(OID_COMP(contentInfo.contentType.value, contentInfo.contentType.length,
      PKCS7_SIGNED_DATA_OID) != 0)
   {
      return ERROR_INVALID_TYPE;
   }

   //Parse signed-data content
   error = pkcs7ParseSignedData(contentInfo.content.value,
      contentInfo.content.length, &signedData);
   //Any error to report?
   if(error)
      return error;

   //The messageData for this type consists of a degenerate certificates-only
   //CMS SignedData message (refer to RFC 8894, section 3.3.2)
   if(signedData.contentInfo.content.length != 0 ||
      signedData.signerInfos.numSignerInfos != 0)
   {
      return ERROR_INVALID_SYNTAX;
   }

   //Debug message
   TRACE_DEBUG("certificates (%" PRIuSIZE " bytes):\r\n", context->certLen);
   asn1DumpObject(context->cert, context->certLen, 0);

   //The reply must contain at least the issued certificate in the certificates
   //field of the SignedData. The reply may contain additional certificates,
   //but the issued certificate must be the leaf certificate (refer to RFC 8894,
   //section 3.3.2.1)
   if(signedData.certificates.raw.length == 0)
      return ERROR_INVALID_SYNTAX;

   //Point to the first certificate
   data = signedData.certificates.raw.value;
   length = signedData.certificates.raw.length;

   //Loop through the certificate
   while(length > 0)
   {
      //Parse certificate
      error = asn1ReadSequence(data, length, &tag);
      //Any error to report?
      if(error)
         return error;

      //Leaf certificate?
      if(tag.totalLength == length)
         break;

      //Next certificate
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Check the length of the issued certificate
   if(length > SCEP_CLIENT_MAX_CERT_LEN)
      return ERROR_RESPONSE_TOO_LARGE;

   //Save the issued certificate
   osMemcpy(context->cert, data, length);
   context->certLen = length;

   //Sucessful processing
   return NO_ERROR;
}

#endif
