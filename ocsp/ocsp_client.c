/**
 * @file ocsp_client.c
 * @brief OCSP client
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
 * @section Description
 *
 * OCSP is a protocol used to determine the current status of a digital
 * certificate without requiring CRLs. Refer to the following RFCs for
 * complete details:
 * - RFC 6960: X.509 Internet Public Key Infrastructure OCSP
 * - RFC 8954: Online Certificate Status Protocol (OCSP) Nonce Extension
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL OCSP_TRACE_LEVEL

//Dependencies
#include "ocsp/ocsp_client.h"
#include "ocsp/ocsp_client_misc.h"
#include "ocsp/ocsp_resp_parse.h"
#include "ocsp/ocsp_resp_validate.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check crypto library configuration
#if (OCSP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief OCSP client initialization
 * @param[in] context Pointer to the OCSP client context
 * @return Error code
 **/

error_t ocspClientInit(OcspClientContext *context)
{
   error_t error;

   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Initializing OCSP client...\r\n");

   //Initialize context
   osMemset(context, 0, sizeof(OcspClientContext));

   //Initialize HTTP client context
   error = httpClientInit(&context->httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //Initialize OCSP client state
   context->state = OCSP_CLIENT_STATE_DISCONNECTED;

   //Default timeout
   context->timeout = OCSP_CLIENT_DEFAULT_TIMEOUT;
   //Default URI
   osStrcpy(context->uri, "/");

   //Successful initialization
   return NO_ERROR;
}


#if (OCSP_CLIENT_TLS_SUPPORT == ENABLED)

/**
 * @brief Register TLS initialization callback function
 * @param[in] context Pointer to the OCSP client context
 * @param[in] callback TLS initialization callback function
 * @return Error code
 **/

error_t ocspClientRegisterTlsInitCallback(OcspClientContext *context,
   OcspClientTlsInitCallback callback)
{
   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->tlsInitCallback = callback;

   //Successful processing
   return NO_ERROR;
}

#endif


/**
 * @brief Set the pseudo-random number generator to be used
 * @param[in] context Pointer to the OCSP client context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t ocspClientSetPrng(OcspClientContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   //Check parameters
   if(context == NULL || prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //PRNG algorithm that will be used to generate nonces
   context->prngAlgo = prngAlgo;
   //PRNG context
   context->prngContext = prngContext;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set communication timeout
 * @param[in] context Pointer to the OCSP client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t ocspClientSetTimeout(OcspClientContext *context, systime_t timeout)
{
   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the domain name of the OCSP server
 * @param[in] context Pointer to the OCSP client context
 * @param[in] host NULL-terminated string containing the host name
 * @return Error code
 **/

error_t ocspClientSetHost(OcspClientContext *context, const char_t *host)
{
   //Check parameters
   if(context == NULL || host == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the host name is acceptable
   if(osStrlen(host) > OCSP_CLIENT_MAX_HOST_LEN)
      return ERROR_INVALID_LENGTH;

   //Save host name
   osStrcpy(context->serverName, host);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set request URI
 * @param[in] context Pointer to the OCSP client context
 * @param[in] uri NULL-terminated string that contains the resource name
 * @return Error code
 **/

error_t ocspClientSetUri(OcspClientContext *context, const char_t *uri)
{
   //Check parameters
   if(context == NULL || uri == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the URI is acceptable
   if(osStrlen(uri) > OCSP_CLIENT_MAX_URI_LEN)
      return ERROR_INVALID_LENGTH;

   //Save the URI of the directory object
   osStrcpy(context->uri, uri);

   //Successful processing
   return NO_ERROR;
}

/**
 * @brief Bind the OCSP client to a particular network interface
 * @param[in] context Pointer to the OCSP client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t ocspClientBindToInterface(OcspClientContext *context,
   NetInterface *interface)
{
   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the OCSP client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the address of the OCSP server
 * @param[in] context Pointer to the OCSP client context
 * @param[in] serverIpAddr IP address of the OCSP server to connect to
 * @param[in] serverPort UDP port number
 * @return Error code
 **/

error_t ocspClientConnect(OcspClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;

   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Establish connection with the HTTP server
   while(!error)
   {
      //Check OCSP client state
      if(context->state == OCSP_CLIENT_STATE_DISCONNECTED)
      {
         //Save the TCP port number to be used
         context->serverPort = serverPort;

#if (OCSP_CLIENT_TLS_SUPPORT == ENABLED)
         //Register TLS initialization callback
         error = httpClientRegisterTlsInitCallback(&context->httpClientContext,
            context->tlsInitCallback);
#endif
         //Check status code
         if(!error)
         {
            //Select HTTP protocol version
            error = httpClientSetVersion(&context->httpClientContext,
               HTTP_VERSION_1_1);
         }

         //Check status code
         if(!error)
         {
            //Set timeout value for blocking operations
            error = httpClientSetTimeout(&context->httpClientContext,
               context->timeout);
         }

         //Check status code
         if(!error)
         {
            //Bind the HTTP client to the relevant network interface
            error = httpClientBindToInterface(&context->httpClientContext,
               context->interface);
         }

         //Check status code
         if(!error)
         {
            //Establish HTTP connection
            context->state = OCSP_CLIENT_STATE_CONNECTING;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_CONNECTING)
      {
         //Establish HTTP connection
         error = httpClientConnect(&context->httpClientContext, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //The HTTP connection is established
            context->state = OCSP_CLIENT_STATE_CONNECTED;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_CONNECTED)
      {
         //The client is connected to the OCSP server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the OCSP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      httpClientClose(&context->httpClientContext);
      //Update OCSP client state
      context->state = OCSP_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Create OCSP request
 * @param[in] context Pointer to the OCSP client context
 * @param[in] cert Certificate to be checked (PEM or DER format)
 * @param[in] certLen Length of the certificate, in bytes
 * @param[in] issuerCert Issuer's certificate (PEM or DER format)
 * @param[in] issuerCertLen Length of the issuer certificate, in bytes
 * @return Error code
 **/

error_t ocspClientCreateRequest(OcspClientContext *context,
   const char_t *cert, size_t certLen, const char_t *issuerCert,
   size_t issuerCertLen)
{
   error_t error;

   //Check parameters
   if(context == NULL || cert == NULL || issuerCert == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check OCSP client state
   if(context->state != OCSP_CLIENT_STATE_CONNECTED &&
      context->state != OCSP_CLIENT_STATE_PARSE_RESP &&
      context->state != OCSP_CLIENT_STATE_VALIDATE_RESP &&
      context->state != OCSP_CLIENT_STATE_RESP_VALIDATED)
   {
      return ERROR_WRONG_STATE;
   }

   //The value of the nonce must be generated using a cryptographically strong
   //pseudorandom number generator
   error = ocspClientGenerateNonce(context);
   //Any error to report?
   if(error)
      return error;

   //Format OCSP request
   error = ocspClientFormatRequest(context, cert, certLen, issuerCert,
      issuerCertLen);
   //Any error to report?
   if(error)
      return error;

   //Update OCSP client state
   context->state = OCSP_CLIENT_STATE_FORMAT_HEADER;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Perform OCSP request/response transaction
 * @param[in] context Pointer to the OCSP client context
 * @return Error code
 **/

error_t ocspClientSendRequest(OcspClientContext *context)
{
   error_t error;
   size_t n;

   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check OCSP client state
      if(context->state == OCSP_CLIENT_STATE_FORMAT_HEADER)
      {
         //Format HTTP request header
         error = ocspClientFormatHeader(context);

         //Check status code
         if(!error)
         {
            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_SEND_HEADER;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_SEND_HEADER)
      {
         //Send HTTP request header
         error = httpClientWriteHeader(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Point to the first byte of the body
            context->bufferPos = 0;

            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_SEND_BODY;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_SEND_BODY)
      {
         //Send HTTP request body
         if(context->bufferPos < context->bufferLen)
         {
            //Send more data
            error = httpClientWriteBody(&context->httpClientContext,
               context->buffer + context->bufferPos,
               context->bufferLen - context->bufferPos, &n, 0);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               context->bufferPos += n;
            }
         }
         else
         {
            //Update HTTP request state
            context->state = OCSP_CLIENT_STATE_RECEIVE_HEADER;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_RECEIVE_HEADER)
      {
         //Receive HTTP response header
         error = httpClientReadHeader(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_PARSE_HEADER;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_PARSE_HEADER)
      {
         //Parse HTTP response header
         error = ocspClientParseHeader(context);

         //Check status code
         if(!error)
         {
            //Flush the receive buffer
            context->bufferLen = 0;
            context->bufferPos = 0;

            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_RECEIVE_BODY;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_RECEIVE_BODY)
      {
         //Receive HTTP response body
         if(context->bufferLen < OCSP_CLIENT_BUFFER_SIZE)
         {
            //Receive more data
            error = httpClientReadBody(&context->httpClientContext,
               context->buffer + context->bufferLen,
               OCSP_CLIENT_BUFFER_SIZE - context->bufferLen, &n, 0);

            //Check status code
            if(error == NO_ERROR)
            {
               //Advance data pointer
               context->bufferLen += n;
            }
            else if(error == ERROR_END_OF_STREAM)
            {
               //The end of the response body has been reached
               error = NO_ERROR;

               //Update OCSP client state
               context->state = OCSP_CLIENT_STATE_CLOSE_BODY;
            }
            else
            {
               //Just for sanity
            }
         }
         else
         {
            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_CLOSE_BODY;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_CLOSE_BODY)
      {
         //Close HTTP response body
         error = httpClientCloseBody(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_PARSE_RESP;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_PARSE_RESP)
      {
         //Parse OCSP response
         error = ocspParseResponse(context->buffer, context->bufferLen,
            &context->ocspResponse);

         //Check status code
         if(!error)
         {
            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_VALIDATE_RESP;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Validate OCSP response
 * @param[in] context Pointer to the OCSP client context
 * @param[in] cert Certificate to be checked (PEM or DER format)
 * @param[in] certLen Length of the certificate, in bytes
 * @param[in] issuerCert Issuer's certificate (PEM or DER format)
 * @param[in] issuerCertLen Length of the issuer certificate, in bytes
 * @return Error code
 **/

error_t ocspClientValidateResponse(OcspClientContext *context,
   const char_t *cert, size_t certLen, const char_t *issuerCert,
   size_t issuerCertLen)
{
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   uint8_t *derIssuerCert;
   size_t derIssuerCertLen;
   X509CertInfo *certInfo;
   X509CertInfo *issuerCertInfo;
   X509Options options;

   //Check parameters
   if(context == NULL || cert == NULL || issuerCert == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check OCSP client state
   if(context->state != OCSP_CLIENT_STATE_VALIDATE_RESP)
      return ERROR_WRONG_STATE;

   //Check response status
   if(context->ocspResponse.responseStatus != OCSP_RESP_STATUS_SUCCESSFUL)
      return ERROR_UNEXPECTED_STATUS;

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

      //Validate OCSP response
      error = ocspValidateResponse(&context->ocspResponse, certInfo,
         issuerCertInfo, context->nonce, context->nonceLen);
      //Any error to report?
      if(error)
         break;

      //Update OCSP client state
      context->state = OCSP_CLIENT_STATE_RESP_VALIDATED;

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
 * @brief Get OCSP response
 * @param[in] context Pointer to the OCSP client context
 * @return Pointer to the received OCSP response
 **/

const OcspResponse *ocspClientGetResponse(OcspClientContext *context)
{
   const OcspResponse *response;

   //Initialize pointer
   response = NULL;

   //Make sure the OCSP client context is valid
   if(context != NULL)
   {
      //Check OCSP client state
      if(context->state == OCSP_CLIENT_STATE_VALIDATE_RESP ||
         context->state == OCSP_CLIENT_STATE_RESP_VALIDATED)
      {
         //Point to the OCSP response
         response = &context->ocspResponse;
      }
   }

   //Return a pointer to the received OCSP response
   return response;
}


/**
 * @brief Get the processing status of the prior request
 * @param[in] context Pointer to the OCSP client context
 * @return Response status
 **/

OcspResponseStatus ocspClientGetResponseStatus(OcspClientContext *context)
{
   OcspResponseStatus responseStatus;

   //Initialize response status
   responseStatus = OCSP_RESP_STATUS_INTERNAL_ERROR;

   //Make sure the OCSP client context is valid
   if(context != NULL)
   {
      //Check OCSP client state
      if(context->state == OCSP_CLIENT_STATE_VALIDATE_RESP ||
         context->state == OCSP_CLIENT_STATE_RESP_VALIDATED)
      {
         //The response status indicates the processing status of the request
         responseStatus = context->ocspResponse.responseStatus;
      }
   }

   //Return response status
   return responseStatus;
}


/**
 * @brief Get the revocation status of the certificate
 * @param[in] context Pointer to the OCSP client context
 * @return Certificate status
 **/

OcspCertStatus ocspClientGetCertificateStatus(OcspClientContext *context)
{
   OcspCertStatus certStatus;
   OcspBasicResponse *basicResponse;

   //Initialize certificate status
   certStatus = OCSP_CERT_STATUS_UNKNOWN;

   //Make sure the OCSP client context is valid
   if(context != NULL)
   {
      //Check OCSP client state
      if(context->state == OCSP_CLIENT_STATE_RESP_VALIDATED)
      {
         //Check response status
         if(context->ocspResponse.responseStatus == OCSP_RESP_STATUS_SUCCESSFUL)
         {
            //Point to the TbsResponseData structure
            basicResponse = &context->ocspResponse.basicResponse;
            //Get the revocation status of the certificate
            certStatus = basicResponse->tbsResponseData.responses[0].certStatus;
         }
      }
   }

   //Return certificate status
   return certStatus;
}


/**
 * @brief Gracefully disconnect from the OCSP server
 * @param[in] context Pointer to the OCSP client context
 * @return Error code
 **/

error_t ocspClientDisconnect(OcspClientContext *context)
{
   error_t error;

   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the OCSP server
   while(!error)
   {
      //Check OCSP client state
      if(context->state == OCSP_CLIENT_STATE_CONNECTED)
      {
         //Gracefully shutdown HTTP connection
         context->state = OCSP_CLIENT_STATE_DISCONNECTING;
      }
      else if(context->state == OCSP_CLIENT_STATE_DISCONNECTING)
      {
         //Gracefully shutdown HTTP connection
         error = httpClientDisconnect(&context->httpClientContext);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close HTTP connection
            httpClientClose(&context->httpClientContext);
            //Update OCSP client state
            context->state = OCSP_CLIENT_STATE_DISCONNECTED;
         }
      }
      else if(context->state == OCSP_CLIENT_STATE_DISCONNECTED)
      {
         //The client is disconnected from the OCSP server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to gracefully disconnect from the OCSP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close HTTP connection
      httpClientClose(&context->httpClientContext);
      //Update OCSP client state
      context->state = OCSP_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the OCSP server
 * @param[in] context Pointer to the OCSP client context
 * @return Error code
 **/

error_t ocspClientClose(OcspClientContext *context)
{
   //Make sure the OCSP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close HTTP connection
   httpClientClose(&context->httpClientContext);
   //Update OCSP client state
   context->state = OCSP_CLIENT_STATE_DISCONNECTED;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release OCSP client context
 * @param[in] context Pointer to the OCSP client context
 **/

void ocspClientDeinit(OcspClientContext *context)
{
   //Make sure the OCSP client context is valid
   if(context != NULL)
   {
      //Release HTTP client context
      httpClientDeinit(&context->httpClientContext);
      //Clear OCSP client context
      osMemset(context, 0, sizeof(OcspClientContext));
   }
}

#endif
