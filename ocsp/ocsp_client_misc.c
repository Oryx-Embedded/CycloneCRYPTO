/**
 * @file ocsp_client_misc.c
 * @brief Helper functions for OCSP client
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
#include "ocsp/ocsp_client.h"
#include "ocsp/ocsp_client_misc.h"
#include "ocsp/ocsp_req_create.h"
#include "ocsp/ocsp_resp_parse.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check crypto library configuration
#if (OCSP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Nonce generation
 * @param[in] context Pointer to the OCSP client context
 * @return Error code
 **/

error_t ocspClientGenerateNonce(OcspClientContext *context)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //The value of the nonce must be generated using a cryptographically
   //strong pseudorandom number generator
   if(context->prngAlgo != NULL && context->prngContext != NULL)
   {
      //If the Nonce extension is present, then the length of the nonce
      //must be at least 1 octet and can be up to 32 octets (refer to
      //RFC 8954, section 2.1)
      error = context->prngAlgo->generate(context->prngContext,
         context->nonce, OCSP_CLIENT_NONCE_SIZE);

      //Check status code
      if(!error)
      {
         //Save the length of the nonce
         context->nonceLen = OCSP_CLIENT_NONCE_SIZE;
      }
   }
   else
   {
      //The Nonce extension is optional
      context->nonceLen = 0;
   }

   //Return status code
   return error;
}


/**
 * @brief Format HTTP request header
 * @param[in] context Pointer to the OCSP client context
 * @return Error code
 **/

error_t ocspClientFormatHeader(OcspClientContext *context)
{
   bool_t defaultPort;

   //Create an HTTP request
   httpClientCreateRequest(&context->httpClientContext);
   httpClientSetMethod(&context->httpClientContext, "POST");
   httpClientSetUri(&context->httpClientContext, context->uri);

#if (OCSP_CLIENT_TLS_SUPPORT == ENABLED)
   //"https" URI scheme?
   if(context->tlsInitCallback != NULL)
   {
      //The default port number is 443 for "https" URI scheme
      defaultPort = (context->serverPort == HTTPS_PORT) ? TRUE : FALSE;
   }
   else
#endif
   //"http" URI scheme?
   {
      //The default port number is 80 for "http" URI scheme
      defaultPort = (context->serverPort == HTTP_PORT) ? TRUE : FALSE;
   }

   //A client must send a Host header field in all HTTP/1.1 requests (refer
   //to RFC 7230, section 5.4)
   if(defaultPort)
   {
      //A host without any trailing port information implies the default port
      //for the service requested
      httpClientAddHeaderField(&context->httpClientContext, "Host",
         context->serverName);
   }
   else
   {
      //Append the port number information to the host
      httpClientFormatHeaderField(&context->httpClientContext,
         "Host", "%s:%" PRIu16, context->serverName, context->serverPort);
   }

   //Add HTTP header fields
   httpClientAddHeaderField(&context->httpClientContext, "User-Agent",
      "Mozilla/5.0");

   httpClientAddHeaderField(&context->httpClientContext, "Content-Type",
      "application/ocsp-request");

   //Specify the length of the request body
   httpClientSetContentLength(&context->httpClientContext, context->bufferLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format OCSP request
 * @param[in] context Pointer to the OCSP client context
 * @param[in] cert Certificate to be checked (PEM or DER format)
 * @param[in] certLen Length of the certificate, in bytes
 * @param[in] issuerCert Issuer's certificate (PEM or DER format)
 * @param[in] issuerCertLen Length of the issuer certificate, in bytes
 * @return Error code
 **/

error_t ocspClientFormatRequest(OcspClientContext *context, const char_t *cert,
   size_t certLen, const char_t *issuerCert, size_t issuerCertLen)
{
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   uint8_t *derIssuerCert;
   size_t derIssuerCertLen;
   X509CertInfo *certInfo;
   X509CertInfo *issuerCertInfo;
   X509Options options;

   //Initialize status code
   error = NO_ERROR;

   //Initialize variables
   derCert = NULL;
   derIssuerCert = NULL;
   certInfo = NULL;
   issuerCertInfo = NULL;

   //Additional certificate parsing options
   options = X509_DEFAULT_OPTIONS;
   options.ignoreUnknownExtensions = TRUE;

   //Start of exception handling block
   do
   {
      //Allocate a memory buffer to store X.509 certificate info
      certInfo = cryptoAllocMem(sizeof(X509CertInfo));
      //Failed to allocate memory?
      if(certInfo == NULL)
      {
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //The OCSP client accepts certificates in either PEM or DER format
      error = pemImportCertificate(cert, certLen, NULL, &derCertLen, NULL);

      //PEM or DER format?
      if(!error)
      {
         //Allocate a memory buffer to hold the DER-encoded certificate
         derCert = cryptoAllocMem(derCertLen);
         //Failed to allocate memory?
         if(derCert == NULL)
         {
            error = ERROR_OUT_OF_MEMORY;
            break;
         }

         //The second pass decodes the PEM certificate
         error = pemImportCertificate(cert, certLen, derCert, &derCertLen,
            NULL);
         //Any error to report?
         if(error)
            break;

         //Parse X.509 certificate
         error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
            &options);
         //Any error to report?
         if(error)
            break;
      }
      else
      {
         //Parse X.509 certificate
         error = x509ParseCertificateEx(cert, certLen, certInfo, &options);
         //Any error to report?
         if(error)
            break;
      }

      //Allocate a memory buffer to store X.509 certificate info
      issuerCertInfo = cryptoAllocMem(sizeof(X509CertInfo));
      //Failed to allocate memory?
      if(certInfo == NULL)
      {
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //The OCSP client accepts certificates in either PEM or DER format
      error = pemImportCertificate(issuerCert, issuerCertLen, NULL,
         &derIssuerCertLen, NULL);

      //PEM or DER format?
      if(!error)
      {
         //Allocate a memory buffer to hold the DER-encoded certificate
         derIssuerCert = cryptoAllocMem(derIssuerCertLen);
         //Failed to allocate memory?
         if(derCert == NULL)
         {
            error = ERROR_OUT_OF_MEMORY;
            break;
         }

         //The second pass decodes the PEM certificate
         error = pemImportCertificate(issuerCert, issuerCertLen, derIssuerCert,
            &derIssuerCertLen, NULL);
         //Any error to report?
         if(error)
            break;

         //Parse X.509 certificate
         error = x509ParseCertificateEx(derIssuerCert, derIssuerCertLen,
            issuerCertInfo, &options);
         //Any error to report?
         if(error)
            break;
      }
      else
      {
         //Parse X.509 certificate
         error = x509ParseCertificateEx(issuerCert, issuerCertLen,
            issuerCertInfo, &options);
         //Any error to report?
         if(error)
            break;
      }

      //Generate an OCSP request
      error = ocspCreateRequest(certInfo, issuerCertInfo, context->nonce,
         context->nonceLen, context->buffer, &context->bufferLen);
      //Any error to report?
      if(error)
         break;

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   if(derCert != NULL)
   {
      cryptoFreeMem(derCert);
   }

   if(derIssuerCert != NULL)
   {
      cryptoFreeMem(derIssuerCert);
   }

   if(certInfo != NULL)
   {
      cryptoFreeMem(certInfo);
   }

   if(issuerCertInfo != NULL)
   {
      cryptoFreeMem(issuerCertInfo);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse HTTP response header
 * @param[in] context Pointer to the OCSP client context
 * @return Error code
 **/

error_t ocspClientParseHeader(OcspClientContext *context)
{
   const char_t *contentType;

   //Retrieve HTTP status code
   context->httpStatusCode = httpClientGetStatus(&context->httpClientContext);

   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->httpStatusCode))
      return ERROR_UNEXPECTED_STATUS;

   //Get the Content-Type header field
   contentType = httpClientGetHeaderField(&context->httpClientContext,
      "Content-Type");

   //Make sure the Content-Type header field is present
   if(contentType == NULL)
      return ERROR_INVALID_RESPONSE;

   //Check the value of the Content-Type header field
   if(osStrcasecmp(contentType, "application/ocsp-response") != 0)
      return ERROR_INVALID_RESPONSE;

   //Successful processing
   return NO_ERROR;
}

#endif
