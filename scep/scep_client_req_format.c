/**
 * @file scep_client_req_format.c
 * @brief SCEP request generation
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
#include "scep/scep_client_req_format.h"
#include "scep/scep_client_misc.h"
#include "pkcs7/pkcs7_format.h"
#include "pkcs7/pkcs7_encrypt.h"
#include "pkcs7/pkcs7_sign_generate.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_format.h"
#include "pkix/x509_csr_parse.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Format PKI message
 * @param[in] context Pointer to the SCEP client context
 * @param[in] messageType SCEP message type
 * @param[out] output Buffer where to format the PKI message
 * @param[out] written Length of the resulting PKI message
 * @return Error code
 **/

error_t scepClientFormatPkiMessage(ScepClientContext *context,
   ScepMessageType messageType, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   time_t currentTime;
   X509CertInfo *certInfo;
   Pkcs7ContentInfo contentInfo;
   Pkcs7AuthenticatedAttributes attributes;
   X509SignAlgoId signatureAlgo;
   char_t buffer[3];

   //The messageType attribute specifies the type of operation performed by the
   //transaction. This attribute must be included in all PKI messages (refer to
   //RFC 8894, section 3.2.1.2)
   osSprintf(buffer, "%u", (uint_t) messageType);

   //When a sender sends a PKI message to a recipient, a fresh senderNonce
   //must be included in the message (refer to RFC 8894, section 3.2.1.5)
   error = context->prngAlgo->generate(context->prngContext,
      context->senderNonce, SCEP_NONCE_SIZE);
   //Any error to report?
   if(error)
      return error;

   //The signed content must be a pkcsPKIEnvelope
   error = scepClientFormatPkcsPkiEnvelope(context, messageType, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Clear authenticatedAttributes structure
   osMemset(&attributes, 0, sizeof(Pkcs7AuthenticatedAttributes));

   //The authenticatedAttributes field must contain a PKCS #9 content-type
   //attribute having as its value the content type of the ContentInfo value
   //being signed (refer to RFC 2315, section 9.2)
   attributes.contentType.value = PKCS7_DATA_OID;
   attributes.contentType.length = sizeof(PKCS7_DATA_OID);

   //Retrieve current time
   currentTime = getCurrentUnixTime();

   //Any real-time clock implemented?
   if(currentTime != 0)
   {
      //Other attribute types that might be useful here, such as signing time,
      //can be included
      convertUnixTimeToDate(currentTime, &attributes.signingTime);
   }

   //At a minimum, all messages must contain a transactionID attribute, a
   //messageType attribute and a fresh senderNonce attribute (refer to RFC 8894,
   //section 3.2.1)
   attributes.numCustomAttributes = 3;

   //Format transactionID attribute
   attributes.customAttributes[0].oid.value = SCEP_TRANSACTION_ID_OID;
   attributes.customAttributes[0].oid.length = sizeof(SCEP_TRANSACTION_ID_OID);
   attributes.customAttributes[0].type = ASN1_TYPE_PRINTABLE_STRING;
   attributes.customAttributes[0].data.value = (uint8_t *) context->transactionId;
   attributes.customAttributes[0].data.length = osStrlen(context->transactionId);

   //Format messageType attribute
   attributes.customAttributes[1].oid.value = SCEP_MESSAGE_TYPE_OID;
   attributes.customAttributes[1].oid.length = sizeof(SCEP_MESSAGE_TYPE_OID);
   attributes.customAttributes[1].type = ASN1_TYPE_PRINTABLE_STRING;
   attributes.customAttributes[1].data.value = (uint8_t *) buffer;
   attributes.customAttributes[1].data.length = osStrlen(buffer);

   //Format senderNonce attribute
   attributes.customAttributes[2].oid.value = SCEP_SENDER_NONCE_OID;
   attributes.customAttributes[2].oid.length = sizeof(SCEP_SENDER_NONCE_OID);
   attributes.customAttributes[2].type = ASN1_TYPE_OCTET_STRING;
   attributes.customAttributes[2].data.value = context->senderNonce;
   attributes.customAttributes[2].data.length = SCEP_NONCE_SIZE;

   //Select signature algorithm
   error = scepClientSelectSignatureAlgo(context, &signatureAlgo);
   //Any error to report?
   if(error)
      return error;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = cryptoAllocMem(sizeof(X509CertInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //The certificate will be either the self-signed one matching the PKCS #10
      //request or the CA-issued one used to authorise a renewal
      error = x509ParseCertificate(context->cert, context->certLen, certInfo);

      //Check status code
      if(!error)
      {
         //During the certificate-enrolment process, the client must use the
         //selected certificate's key when signing the CMS envelope. This
         //certificate will be either the self-signed one matching the PKCS #10
         //request or the CA-issued one used to authorise a renewal (refer to
         //RFC 8894, section 2.3)
         error = pkcs7GenerateSignedData(context->prngAlgo,
            context->prngContext, output, n, certInfo, &attributes, NULL,
            &signatureAlgo, &context->rsaPrivateKey, output, &n);
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

   //The general syntax for content exchanged between entities associates a
   //content type with content (refer to RFC 2315, section 7)
   osMemset(&contentInfo, 0, sizeof(Pkcs7ContentInfo));
   contentInfo.contentType.value = PKCS7_SIGNED_DATA_OID;
   contentInfo.contentType.length = sizeof(PKCS7_SIGNED_DATA_OID);
   contentInfo.content.value = output;
   contentInfo.content.length = n;

   //Format ContentInfo structure
   error = pkcs7FormatContentInfo(&contentInfo, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("pkiMessage (%" PRIuSIZE " bytes):\r\n", n);
   asn1DumpObject(output, n, 0);

   //Total length of the ASN.1 structure
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format pkcsPKIEnvelope structure
 * @param[in] context Pointer to the SCEP client context
 * @param[in] messageType SCEP message type
 * @param[out] output Buffer where to format the pkcsPKIEnvelope structure
 * @param[out] written Length of the resulting pkcsPKIEnvelope structure
 * @return Error code
 **/

error_t scepClientFormatPkcsPkiEnvelope(ScepClientContext *context,
   ScepMessageType messageType, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   X509CertInfo *certInfo;
   Pkcs7ContentInfo contentInfo;
   Pkcs7ContentEncrAlgo contentEncrAlgo;

   //Check the length of the CSR
   if(context->csrLen == 0)
      return ERROR_INVALID_CSR;

   //Select content encryption algorithm
   error = scepClientSelectContentEncrAlgo(context, &contentEncrAlgo);
   //Any error to report?
   if(error)
      return error;

   //Check SCEP message type
   if(messageType == SCEP_MSG_TYPE_PKCS_REQ ||
      messageType == SCEP_MSG_TYPE_RENEWAL_REQ)
   {
      //The messageData for this type consists of a PKCS #10 certificate
      //request (refer to RFC 8894, section 3.3.1)
      osMemcpy(context->buffer, context->csr, context->csrLen);
      n = context->csrLen;
   }
   else if(messageType == SCEP_MSG_TYPE_CERT_POLL)
   {
      //The messageData for this type consists of an IssuerAndSubject (refer
      //to RFC 8894, section 3.3.3)
      error = scepClientFormatIssuerAndSubject(context, output, &n);
   }
   else
   {
      //Unknown message type
      error = ERROR_INVALID_TYPE;
   }

   //Any error to report?
   if(error)
      return error;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = cryptoAllocMem(sizeof(X509CertInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //Parse CA certificate
      error = scepClientParseCaCert(context, certInfo);

      //Check status code
      if(!error)
      {
         //Encrypt enveloped-data content
         error = pkcs7EncryptEnvelopedData(context->prngAlgo,
            context->prngContext, certInfo, &contentEncrAlgo, context->buffer,
            n, output, &n);
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

   //The general syntax for content exchanged between entities associates a
   //content type with content (refer to RFC 2315, section 7)
   contentInfo.contentType.value = PKCS7_ENVELOPED_DATA_OID;
   contentInfo.contentType.length = sizeof(PKCS7_ENVELOPED_DATA_OID);
   contentInfo.content.value = output;
   contentInfo.content.length = n;

   //Format ContentInfo structure
   error = pkcs7FormatContentInfo(&contentInfo, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("pkcsPKIEnvelope (%" PRIuSIZE " bytes):\r\n", n);
   asn1DumpObject(output, n, 0);

   //Total length of the ASN.1 structure
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format IssuerAndSubject structure
 * @param[in] context Pointer to the SCEP client context
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t scepClientFormatIssuerAndSubject(ScepClientContext *context,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509CsrInfo *csrInfo;
   X509CertificateInfo *certInfo;

   //Point to the buffer where to write the ASN.1 structure
   p = output;
   //Length of the ASN.1 structure
   length = 0;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = cryptoAllocMem(sizeof(X509CertInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //Parse CA certificate
      error = scepClientParseCaCert(context, certInfo);

      //Check status code
      if(!error)
      {
         //Format issuer field
         error = x509FormatName(&certInfo->tbsCert.subject, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
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

   //Allocate a memory buffer to store CSR info
   csrInfo = cryptoAllocMem(sizeof(X509CsrInfo));

   //Successful memory allocation?
   if(csrInfo != NULL)
   {
      //Parse the PKCS #10 certificate request
      error = x509ParseCsr(context->csr, context->csrLen, csrInfo);

      //Check status code
      if(!error)
      {
         //Format subject field
         error = x509FormatName(&csrInfo->certReqInfo.subject, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;
      }

      //Release previously allocated memory
      cryptoFreeMem(csrInfo);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Any error to report?
   if(error)
      return error;

   //The IssuerAndSubject structure is encapsulated within a sequence
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

#endif
