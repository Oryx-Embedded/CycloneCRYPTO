/**
 * @file scep_client_transport.c
 * @brief HTTP transport mechanism
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
#include "scep/scep_client_transport.h"
#include "debug.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send HTTP request
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientSendRequest(ScepClientContext *context)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check HTTP request state
   if(context->requestState == SCEP_REQ_STATE_SEND_HEADER)
   {
      //Send HTTP request header
      error = httpClientWriteHeader(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Check whether the HTTP request contains a body
         if(context->bufferLen > 0)
         {
            //Point to the first byte of the body
            context->bufferPos = 0;

            //Send HTTP request body
            context->requestState = SCEP_REQ_STATE_SEND_BODY;
         }
         else
         {
            //Receive HTTP response header
            context->requestState = SCEP_REQ_STATE_RECEIVE_HEADER;
         }
      }
   }
   else if(context->requestState == SCEP_REQ_STATE_SEND_BODY)
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
         context->requestState = SCEP_REQ_STATE_RECEIVE_HEADER;
      }
   }
   else if(context->requestState == SCEP_REQ_STATE_RECEIVE_HEADER)
   {
      //Receive HTTP response header
      error = httpClientReadHeader(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_PARSE_HEADER;
      }
   }
   else if(context->requestState == SCEP_REQ_STATE_PARSE_HEADER)
   {
      //Parse HTTP response header
      error = scepClientParseResponseHeader(context);

      //Check status code
      if(!error)
      {
         //Flush the receive buffer
         context->bufferLen = 0;
         context->bufferPos = 0;

         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_RECEIVE_BODY;
      }
   }
   else if(context->requestState == SCEP_REQ_STATE_RECEIVE_BODY)
   {
      //Receive HTTP response body
      if(context->bufferLen < SCEP_CLIENT_BUFFER_SIZE)
      {
         //Receive more data
         error = httpClientReadBody(&context->httpClientContext,
            context->buffer + context->bufferLen,
            SCEP_CLIENT_BUFFER_SIZE - context->bufferLen, &n, 0);

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

            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_CLOSE_BODY;
         }
         else
         {
            //Just for sanity
         }
      }
      else
      {
         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_CLOSE_BODY;
      }
   }
   else if(context->requestState == SCEP_REQ_STATE_CLOSE_BODY)
   {
      //Close HTTP response body
      error = httpClientCloseBody(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_COMPLETE;
      }
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Format HTTP request header
 * @param[in] context Pointer to the SCEP client context
 * @param[in] method NULL-terminating string containing the HTTP method
 * @param[in] operation NULL-terminating string containing the SCEP operation
 * @return Error code
 **/

error_t scepClientFormatRequestHeader(ScepClientContext *context,
   const char_t *method, const char_t *operation)
{
   error_t error;
   bool_t defaultPort;
   HttpClientContext *httpClientContext;

   //Point to the HTTP client context
   httpClientContext = &context->httpClientContext;

   //Create a new HTTP request
   error = httpClientCreateRequest(httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //SCEP uses the HTTP POST and GET methods to exchange information with the
   //CA (refer to RFC 8894, section 4.1)
   error = httpClientSetMethod(httpClientContext, method);
   //Any error to report?
   if(error)
      return error;

   //SCEPPATH is the HTTP URL path for accessing the CA
   error = httpClientSetUri(httpClientContext, context->uri);
   //Any error to report?
   if(error)
      return error;

   //OPERATION depends on the SCEP transaction
   error = httpClientAddQueryParam(httpClientContext, "operation", operation);
   //Any error to report?
   if(error)
      return error;

#if (SCEP_CLIENT_TLS_SUPPORT == ENABLED)
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
      error = httpClientAddHeaderField(httpClientContext, "Host",
         context->serverName);
   }
   else
   {
      //Append the port number information to the host
      error = httpClientFormatHeaderField(httpClientContext,
         "Host", "%s:%" PRIu16, context->serverName, context->serverPort);
   }

   //Any error to report?
   if(error)
      return error;

   //Set User-Agent header field
   error = httpClientAddHeaderField(httpClientContext, "User-Agent",
      "Mozilla/5.0");
   //Any error to report?
   if(error)
      return error;

   //POST request?
   if(osStrcmp(method, "POST") == 0)
   {
      //When implemented using HTTP POST, the message is sent with a
      //Content-Type of "application/x-pki-message" (refer to RFC 8894,
      //section 4.3)
      error = httpClientAddHeaderField(httpClientContext, "Content-Type",
         "application/x-pki-message");
      //Any error to report?
      if(error)
         return error;

      //Specify the length of the request body
      error = httpClientSetContentLength(httpClientContext, context->bufferLen);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //The HTTP request body is empty
      context->bufferLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HTTP response header
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientParseResponseHeader(ScepClientContext *context)
{
   size_t n;
   char_t *p;
   const char_t *contentType;

   //Get HTTP response status code
   context->statusCode = httpClientGetStatus(&context->httpClientContext);

   //Get the Content-Type header field
   contentType = httpClientGetHeaderField(&context->httpClientContext,
      "Content-Type");

   //Content-Type header field found?
   if(contentType != NULL)
   {
      //Retrieve the header field value
      n = osStrlen(contentType);
      //Limit the length of the string
      n = MIN(n, SCEP_CLIENT_MAX_CONTENT_TYPE_LEN);

      //Save the media type
      osStrncpy(context->contentType, contentType, n);
      //Properly terminate the string with a NULL character
      context->contentType[n] = '\0';

      //Discard the parameters that may follow the type/subtype
      osStrtok_r(context->contentType, "; \t", &p);
   }
   else
   {
      //The Content-Type header field is not present in the response
      context->contentType[0] = '\0';
   }

   //Successful processing
   return NO_ERROR;
}

#endif
