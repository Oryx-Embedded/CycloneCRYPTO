/**
 * @file ocsp_client.h
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

#ifndef _OCSP_CLIENT_H
#define _OCSP_CLIENT_H

//Dependencies
#include "core/net.h"
#include "http/http_client.h"
#include "ocsp/ocsp_common.h"

//OCSP client support
#ifndef OCSP_CLIENT_SUPPORT
   #define OCSP_CLIENT_SUPPORT DISABLED
#elif (OCSP_CLIENT_SUPPORT != ENABLED && OCSP_CLIENT_SUPPORT != DISABLED)
   #error OCSP_CLIENT_SUPPORT parameter is not valid
#endif

//OCSP over HTTPS
#ifndef OCSP_CLIENT_TLS_SUPPORT
   #define OCSP_CLIENT_TLS_SUPPORT DISABLED
#elif (OCSP_CLIENT_TLS_SUPPORT != ENABLED && OCSP_CLIENT_TLS_SUPPORT != DISABLED)
   #error OCSP_CLIENT_TLS_SUPPORT parameter is not valid
#endif

//Default timeout
#ifndef OCSP_CLIENT_DEFAULT_TIMEOUT
   #define OCSP_CLIENT_DEFAULT_TIMEOUT 20000
#elif (OCSP_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error OCSP_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef OCSP_CLIENT_BUFFER_SIZE
   #define OCSP_CLIENT_BUFFER_SIZE 2048
#elif (OCSP_CLIENT_BUFFER_SIZE < 512)
   #error OCSP_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of host names
#ifndef OCSP_CLIENT_MAX_HOST_LEN
   #define OCSP_CLIENT_MAX_HOST_LEN 64
#elif (OCSP_CLIENT_MAX_HOST_LEN < 1)
   #error OCSP_CLIENT_MAX_HOST_LEN parameter is not valid
#endif

//Maximum length of URIs
#ifndef OCSP_CLIENT_MAX_URI_LEN
   #define OCSP_CLIENT_MAX_URI_LEN 32
#elif (OCSP_CLIENT_MAX_URI_LEN < 1)
   #error OCSP_CLIENT_MAX_URI_LEN parameter is not valid
#endif

//Nonce size
#ifndef OCSP_CLIENT_NONCE_SIZE
   #define OCSP_CLIENT_NONCE_SIZE 16
#elif (OCSP_CLIENT_NONCE_SIZE < 1 || OCSP_CLIENT_NONCE_SIZE > 32)
   #error OCSP_CLIENT_NONCE_SIZE parameter is not valid
#endif

//Application specific context
#ifndef OCSP_CLIENT_PRIVATE_CONTEXT
   #define OCSP_CLIENT_PRIVATE_CONTEXT
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief OCSP client states
 **/

typedef enum
{
   OCSP_CLIENT_STATE_DISCONNECTED   = 0,
   OCSP_CLIENT_STATE_CONNECTING     = 1,
   OCSP_CLIENT_STATE_CONNECTED      = 2,
   OCSP_CLIENT_STATE_FORMAT_HEADER = 3,
   OCSP_CLIENT_STATE_SEND_HEADER    = 4,
   OCSP_CLIENT_STATE_SEND_BODY      = 5,
   OCSP_CLIENT_STATE_RECEIVE_HEADER = 6,
   OCSP_CLIENT_STATE_PARSE_HEADER   = 7,
   OCSP_CLIENT_STATE_RECEIVE_BODY   = 8,
   OCSP_CLIENT_STATE_CLOSE_BODY     = 9,
   OCSP_CLIENT_STATE_PARSE_RESP     = 10,
   OCSP_CLIENT_STATE_VALIDATE_RESP  = 11,
   OCSP_CLIENT_STATE_RESP_VALIDATED = 12,
   OCSP_CLIENT_STATE_DISCONNECTING  = 13
} OcspClientState;


//HTTPS supported?
#if (OCSP_CLIENT_TLS_SUPPORT == ENABLED)

/**
 * @brief TLS initialization callback function
 **/

typedef error_t (*OcspClientTlsInitCallback)(HttpClientContext *context,
   TlsContext *tlsContext);

#endif


/**
 * @brief OCSP client context
 **/

typedef struct
{
   OcspClientState state;                           ///<OCSP client state
   NetInterface *interface;                         ///<Underlying network interface
   systime_t timeout;                               ///<Timeout value
   const PrngAlgo *prngAlgo;                        ///<Pseudo-random number generator to be used
   void *prngContext;                               ///<Pseudo-random number generator context
   HttpClientContext httpClientContext;             ///<HTTP client context
#if (OCSP_CLIENT_TLS_SUPPORT == ENABLED)
   OcspClientTlsInitCallback tlsInitCallback;       ///<TLS initialization callback function
#endif
   char_t serverName[OCSP_CLIENT_MAX_HOST_LEN + 1]; ///<Host name of the OCSP server
   uint16_t serverPort;                             ///<TCP port number
   char_t uri[OCSP_CLIENT_MAX_URI_LEN + 1];         ///<URI
   uint8_t nonce[OCSP_CLIENT_NONCE_SIZE];           ///<Random nonce
   size_t nonceLen;                                 ///<Length of the nonce, in bytes
   uint8_t buffer[OCSP_CLIENT_BUFFER_SIZE];         ///<Memory buffer for input/output operations
   size_t bufferLen;                                ///<Length of the buffer, in bytes
   size_t bufferPos;                                ///<Current position in the buffer
   uint_t httpStatusCode;                           ///<HTTP status code
   OcspResponse ocspResponse;                       ///<OCSP response
   OCSP_CLIENT_PRIVATE_CONTEXT                      ///<Application specific context
} OcspClientContext;


//OCSP client related functions
error_t ocspClientInit(OcspClientContext *context);

#if (OCSP_CLIENT_TLS_SUPPORT == ENABLED)

error_t ocspClientRegisterTlsInitCallback(OcspClientContext *context,
   OcspClientTlsInitCallback callback);

#endif

error_t ocspClientSetPrng(OcspClientContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t ocspClientSetTimeout(OcspClientContext *context, systime_t timeout);

error_t ocspClientSetHost(OcspClientContext *context, const char_t *host);
error_t ocspClientSetUri(OcspClientContext *context, const char_t *uri);

error_t ocspClientBindToInterface(OcspClientContext *context,
   NetInterface *interface);

error_t ocspClientConnect(OcspClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t ocspClientCreateRequest(OcspClientContext *context,
   const char_t *cert, size_t certLen, const char_t *issuerCert,
   size_t issuerCertLen);

error_t ocspClientSendRequest(OcspClientContext *context);

error_t ocspClientValidateResponse(OcspClientContext *context,
   const char_t *cert, size_t certLen, const char_t *issuerCert,
   size_t issuerCertLen);

const OcspResponse *ocspClientGetResponse(OcspClientContext *context);
OcspResponseStatus ocspClientGetResponseStatus(OcspClientContext *context);
OcspCertStatus ocspClientGetCertificateStatus(OcspClientContext *context);

error_t ocspClientDisconnect(OcspClientContext *context);
error_t ocspClientClose(OcspClientContext *context);

void ocspClientDeinit(OcspClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
