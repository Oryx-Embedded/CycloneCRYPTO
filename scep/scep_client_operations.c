/**
 * @file scep_client_operations.c
 * @brief SCEP operations
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
#include "scep/scep_client_operations.h"
#include "scep/scep_client_req_format.h"
#include "scep/scep_client_resp_parse.h"
#include "scep/scep_client_transport.h"
#include "debug.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Perform GetCACaps operation
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientSendGetCaCaps(ScepClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == SCEP_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating GetCACaps request...\r\n");

         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_FORMAT_HEADER;
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_HEADER)
      {
         //This message requests capabilities from a CA (refer to RFC 8894,
         //section 3.5.1)
         error = scepClientFormatRequestHeader(context, "GET", "GetCACaps");

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending GetCACaps request...\r\n");

            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_SEND_HEADER ||
         context->requestState == SCEP_REQ_STATE_SEND_BODY ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == SCEP_REQ_STATE_PARSE_HEADER ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_BODY ||
         context->requestState == SCEP_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = scepClientSendRequest(context);
      }
      else if(context->requestState == SCEP_REQ_STATE_COMPLETE)
      {
         //Debug message
         TRACE_INFO("Parsing GetCACaps response...\r\n");

         //Parse the body of the HTTP response
         error = scepClientParseGetCaCapsResponse(context);

         //The HTTP transaction is complete
         context->requestState = SCEP_REQ_STATE_INIT;
         break;
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
 * @brief Perform GetCACert operation
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientSendGetCaCert(ScepClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == SCEP_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating GetCACert request...\r\n");

         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_FORMAT_HEADER;
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_HEADER)
      {
         //To get the CA certificate(s), the client sends a GetCACert message
         //to the CA (refer to RFC 8894, section 4.2)
         error = scepClientFormatRequestHeader(context, "GET", "GetCACert");

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending GetCACert request...\r\n");

            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_SEND_HEADER ||
         context->requestState == SCEP_REQ_STATE_SEND_BODY ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == SCEP_REQ_STATE_PARSE_HEADER ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_BODY ||
         context->requestState == SCEP_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = scepClientSendRequest(context);
      }
      else if(context->requestState == SCEP_REQ_STATE_COMPLETE)
      {
         //Debug message
         TRACE_INFO("Parsing GetCaCert response...\r\n");

         //Parse the body of the HTTP response
         error = scepClientParseGetCaCertResponse(context);

         //The HTTP transaction is complete
         context->requestState = SCEP_REQ_STATE_INIT;
         break;
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
 * @brief Perform PKCSReq operation
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientSendPkcsReq(ScepClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == SCEP_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating PKCSReq request...\r\n");

         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_BODY)
      {
         //The PKCSReq message is used to perform a certificate enrolment
         //transaction (refer to RFC 8555, section 4.3)
         error = scepClientFormatPkiMessage(context, SCEP_MSG_TYPE_PKCS_REQ,
            context->buffer, &context->bufferLen);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_HEADER)
      {
         //Check is the the remote CA supports POST
         if((context->caCaps & SCEP_CA_CAPS_POST_PKI_OPERATION) != 0)
         {
            //If the remote CA supports POST, the CMS-encoded SCEP messages
            //must be sent via HTTP POST instead of HTTP GET (refer to RFC 8894,
            //section 4.1)
            error = scepClientFormatRequestHeader(context, "POST",
               "PKIOperation");
         }
         else
         {
            //For historical reasons, implementations may support communications
            //of binary data via HTTP GET (refer to RFC 8894, section 2.9)
            error = ERROR_UNSUPPORTED_FEATURE;
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending PKCSReq request...\r\n");

            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_SEND_HEADER ||
         context->requestState == SCEP_REQ_STATE_SEND_BODY ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == SCEP_REQ_STATE_PARSE_HEADER ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_BODY ||
         context->requestState == SCEP_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = scepClientSendRequest(context);
      }
      else if(context->requestState == SCEP_REQ_STATE_COMPLETE)
      {
         //Debug message
         TRACE_INFO("Parsing CertRep response...\r\n");

         //Parse CertRep message
         error = scepClientParseCertResponse(context);

         //The HTTP transaction is complete
         context->requestState = SCEP_REQ_STATE_INIT;
         break;
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
 * @brief Perform RenewalReq operation
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientSendRenewalReq(ScepClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == SCEP_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating RenewalReq request...\r\n");

         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_BODY)
      {
         //The RenewalReq message is used to perform a certificate renewal
         //transaction (refer to RFC 8555, section 4.3)
         error = scepClientFormatPkiMessage(context, SCEP_MSG_TYPE_RENEWAL_REQ,
            context->buffer, &context->bufferLen);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_HEADER)
      {
         //Check is the the remote CA supports POST
         if((context->caCaps & SCEP_CA_CAPS_POST_PKI_OPERATION) != 0)
         {
            //If the remote CA supports POST, the CMS-encoded SCEP messages
            //must be sent via HTTP POST instead of HTTP GET (refer to RFC 8894,
            //section 4.1)
            error = scepClientFormatRequestHeader(context, "POST",
               "PKIOperation");
         }
         else
         {
            //For historical reasons, implementations may support communications
            //of binary data via HTTP GET (refer to RFC 8894, section 2.9)
            error = ERROR_UNSUPPORTED_FEATURE;
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending RenewalReq request...\r\n");

            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_SEND_HEADER ||
         context->requestState == SCEP_REQ_STATE_SEND_BODY ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == SCEP_REQ_STATE_PARSE_HEADER ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_BODY ||
         context->requestState == SCEP_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = scepClientSendRequest(context);
      }
      else if(context->requestState == SCEP_REQ_STATE_COMPLETE)
      {
         //Debug message
         TRACE_INFO("Parsing CertRep response...\r\n");

         //Parse CertRep message
         error = scepClientParseCertResponse(context);

         //The HTTP transaction is complete
         context->requestState = SCEP_REQ_STATE_INIT;
         break;
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
 * @brief Perform CertPoll operation
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientSendCertPoll(ScepClientContext *context)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == SCEP_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_INFO("Generating CertPoll request...\r\n");

         //Update HTTP request state
         context->requestState = SCEP_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_BODY)
      {
         //The CertPoll message is used for certificate polling (refer to
         //RFC 8555, section 3.3.3)
         error = scepClientFormatPkiMessage(context, SCEP_MSG_TYPE_CERT_POLL,
            context->buffer, &context->bufferLen);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_FORMAT_HEADER)
      {
         //Check is the the remote CA supports POST
         if((context->caCaps & SCEP_CA_CAPS_POST_PKI_OPERATION) != 0)
         {
            //If the remote CA supports POST, the CMS-encoded SCEP messages
            //must be sent via HTTP POST instead of HTTP GET (refer to RFC 8894,
            //section 4.1)
            error = scepClientFormatRequestHeader(context, "POST",
               "PKIOperation");
         }
         else
         {
            //For historical reasons, implementations may support communications
            //of binary data via HTTP GET (refer to RFC 8894, section 2.9)
            error = ERROR_UNSUPPORTED_FEATURE;
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_INFO("Sending CertPoll request...\r\n");

            //Update HTTP request state
            context->requestState = SCEP_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == SCEP_REQ_STATE_SEND_HEADER ||
         context->requestState == SCEP_REQ_STATE_SEND_BODY ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == SCEP_REQ_STATE_PARSE_HEADER ||
         context->requestState == SCEP_REQ_STATE_RECEIVE_BODY ||
         context->requestState == SCEP_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = scepClientSendRequest(context);
      }
      else if(context->requestState == SCEP_REQ_STATE_COMPLETE)
      {
         //Debug message
         TRACE_INFO("Parsing CertRep response...\r\n");

         //Parse CertRep message
         error = scepClientParseCertResponse(context);

         //The HTTP transaction is complete
         context->requestState = SCEP_REQ_STATE_INIT;
         break;
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

#endif
