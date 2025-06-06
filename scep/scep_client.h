/**
 * @file scep_client.h
 * @brief SCEP client
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

#ifndef _SCEP_CLIENT_H
#define _SCEP_CLIENT_H

//Dependencies
#include "core/net.h"
#include "http/http_client.h"
#include "scep/scep_common.h"

//SCEP client support
#ifndef SCEP_CLIENT_SUPPORT
   #define SCEP_CLIENT_SUPPORT DISABLED
#elif (SCEP_CLIENT_SUPPORT != ENABLED && SCEP_CLIENT_SUPPORT != DISABLED)
   #error SCEP_CLIENT_SUPPORT parameter is not valid
#endif

//SCEP over HTTPS
#ifndef SCEP_CLIENT_TLS_SUPPORT
   #define SCEP_CLIENT_TLS_SUPPORT DISABLED
#elif (SCEP_CLIENT_TLS_SUPPORT != ENABLED && SCEP_CLIENT_TLS_SUPPORT != DISABLED)
   #error SCEP_CLIENT_TLS_SUPPORT parameter is not valid
#endif

//Triple DES encryption support (weak)
#ifndef SCEP_CLIENT_3DES_SUPPORT
   #define SCEP_CLIENT_3DES_SUPPORT DISABLED
#elif (SCEP_CLIENT_3DES_SUPPORT != ENABLED && SCEP_CLIENT_3DES_SUPPORT != DISABLED)
   #error SCEP_CLIENT_3DES_SUPPORT parameter is not valid
#endif

//AES encryption support
#ifndef SCEP_CLIENT_AES_SUPPORT
   #define SCEP_CLIENT_AES_SUPPORT ENABLED
#elif (SCEP_CLIENT_AES_SUPPORT != ENABLED && SCEP_CLIENT_AES_SUPPORT != DISABLED)
   #error SCEP_CLIENT_AES_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef SCEP_CLIENT_SHA1_SUPPORT
   #define SCEP_CLIENT_SHA1_SUPPORT DISABLED
#elif (SCEP_CLIENT_SHA1_SUPPORT != ENABLED && SCEP_CLIENT_SHA1_SUPPORT != DISABLED)
   #error SCEP_CLIENT_SHA1_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef SCEP_CLIENT_SHA256_SUPPORT
   #define SCEP_CLIENT_SHA256_SUPPORT ENABLED
#elif (SCEP_CLIENT_SHA256_SUPPORT != ENABLED && SCEP_CLIENT_SHA256_SUPPORT != DISABLED)
   #error SCEP_CLIENT_SHA256_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef SCEP_CLIENT_SHA512_SUPPORT
   #define SCEP_CLIENT_SHA512_SUPPORT DISABLED
#elif (SCEP_CLIENT_SHA512_SUPPORT != ENABLED && SCEP_CLIENT_SHA512_SUPPORT != DISABLED)
   #error SCEP_CLIENT_SHA512_SUPPORT parameter is not valid
#endif

//RSA key support
#ifndef SCEP_CLIENT_RSA_SUPPORT
   #define SCEP_CLIENT_RSA_SUPPORT ENABLED
#elif (SCEP_CLIENT_RSA_SUPPORT != ENABLED && SCEP_CLIENT_RSA_SUPPORT != DISABLED)
   #error SCEP_CLIENT_RSA_SUPPORT parameter is not valid
#endif

//Default timeout
#ifndef SCEP_CLIENT_DEFAULT_TIMEOUT
   #define SCEP_CLIENT_DEFAULT_TIMEOUT 20000
#elif (SCEP_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error SCEP_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef SCEP_CLIENT_BUFFER_SIZE
   #define SCEP_CLIENT_BUFFER_SIZE 8192
#elif (SCEP_CLIENT_BUFFER_SIZE < 512)
   #error SCEP_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of host names
#ifndef SCEP_CLIENT_MAX_HOST_LEN
   #define SCEP_CLIENT_MAX_HOST_LEN 64
#elif (SCEP_CLIENT_MAX_HOST_LEN < 1)
   #error SCEP_CLIENT_MAX_HOST_LEN parameter is not valid
#endif

//Maximum length of URIs
#ifndef SCEP_CLIENT_MAX_URI_LEN
   #define SCEP_CLIENT_MAX_URI_LEN 32
#elif (SCEP_CLIENT_MAX_URI_LEN < 1)
   #error SCEP_CLIENT_MAX_URI_LEN parameter is not valid
#endif

//Maximum length of media types
#ifndef SCEP_CLIENT_MAX_CONTENT_TYPE_LEN
   #define SCEP_CLIENT_MAX_CONTENT_TYPE_LEN 40
#elif (SCEP_CLIENT_MAX_CONTENT_TYPE_LEN < 1)
   #error SCEP_CLIENT_MAX_CONTENT_TYPE_LEN parameter is not valid
#endif

//Maximum length of CSR
#ifndef SCEP_CLIENT_MAX_CSR_LEN
   #define SCEP_CLIENT_MAX_CSR_LEN 1024
#elif (SCEP_CLIENT_MAX_CSR_LEN < 1)
   #error SCEP_CLIENT_MAX_CSR_LEN parameter is not valid
#endif

//Maximum length of certificate
#ifndef SCEP_CLIENT_MAX_CERT_LEN
   #define SCEP_CLIENT_MAX_CERT_LEN 2048
#elif (SCEP_CLIENT_MAX_CERT_LEN < 1)
   #error SCEP_CLIENT_MAX_CERT_LEN parameter is not valid
#endif

//Maximum length of CA certificate chain
#ifndef SCEP_CLIENT_MAX_CA_CERT_LEN
   #define SCEP_CLIENT_MAX_CA_CERT_LEN 4096
#elif (SCEP_CLIENT_MAX_CA_CERT_LEN < 1)
   #error SCEP_CLIENT_MAX_CA_CERT_LEN parameter is not valid
#endif

//Transaction identifier size
#ifndef SCEP_CLIENT_TRANSACTION_ID_SIZE
   #define SCEP_CLIENT_TRANSACTION_ID_SIZE 16
#elif (SCEP_CLIENT_TRANSACTION_ID_SIZE < 1 || SCEP_CLIENT_TRANSACTION_ID_SIZE > 32)
   #error SCEP_CLIENT_TRANSACTION_ID_SIZE parameter is not valid
#endif

//Application specific context
#ifndef SCEP_CLIENT_PRIVATE_CONTEXT
   #define SCEP_CLIENT_PRIVATE_CONTEXT
#endif

//Forward declaration of ScepClientContext structure
struct _ScepClientContext;
#define ScepClientContext struct _ScepClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SCEP client states
 **/

typedef enum
{
   SCEP_CLIENT_STATE_DISCONNECTED         = 0,
   SCEP_CLIENT_STATE_CONNECTING           = 1,
   SCEP_CLIENT_STATE_CONNECTED            = 2,
   SCEP_CLIENT_STATE_GET_CA_CAPS          = 3,
   SCEP_CLIENT_STATE_GET_CA               = 4,
   SCEP_CLIENT_STATE_CSR_GEN              = 5,
   SCEP_CLIENT_STATE_SELF_SIGNED_CERT_GEN = 6,
   SCEP_CLIENT_STATE_TRANSACTION_ID_GEN   = 7,
   SCEP_CLIENT_STATE_PKCS_REQ             = 8,
   SCEP_CLIENT_STATE_RENEWAL_REQ          = 9,
   SCEP_CLIENT_STATE_CERT_POLL            = 10,
   SCEP_CLIENT_STATE_DISCONNECTING        = 11
} ScepClientState;


/**
 * @brief HTTP request states
 */

typedef enum
{
   SCEP_REQ_STATE_INIT           = 0,
   SCEP_REQ_STATE_FORMAT_HEADER  = 1,
   SCEP_REQ_STATE_SEND_HEADER    = 2,
   SCEP_REQ_STATE_FORMAT_BODY    = 3,
   SCEP_REQ_STATE_SEND_BODY      = 4,
   SCEP_REQ_STATE_RECEIVE_HEADER = 5,
   SCEP_REQ_STATE_PARSE_HEADER   = 6,
   SCEP_REQ_STATE_RECEIVE_BODY   = 7,
   SCEP_REQ_STATE_CLOSE_BODY     = 8,
   SCEP_REQ_STATE_COMPLETE       = 9
} ScepRequestState;


//HTTPS supported?
#if (SCEP_CLIENT_TLS_SUPPORT == ENABLED)

/**
 * @brief TLS initialization callback function
 **/

typedef error_t (*ScepClientTlsInitCallback)(HttpClientContext *context,
   TlsContext *tlsContext);

#endif


/**
 * @brief CA certificate verification callback function
 **/

typedef error_t (*ScepClientCaCertVerifyCallback)(ScepClientContext *context,
   const X509CertInfo *certInfo);


/**
 * @brief CSR generation callback function
 **/

typedef error_t (*ScepClientCsrGenCallback)(ScepClientContext *context,
   uint8_t *buffer, size_t size, size_t *length);


/**
 * @brief Self-signed certificate generation callback function
 **/

typedef error_t (*ScepClientSelfSignedCertGenCallback)(ScepClientContext *context,
   uint8_t *buffer, size_t size, size_t *length);


/**
 * @brief SCEP client context
 **/

struct _ScepClientContext
{
   ScepClientState state;                                    ///<SCEP client state
   ScepRequestState requestState;                            ///<HTTP request state
   NetInterface *interface;                                  ///<Underlying network interface
   systime_t timeout;                                        ///<Timeout value
   const PrngAlgo *prngAlgo;                                 ///<Pseudo-random number generator to be used
   void *prngContext;                                        ///<Pseudo-random number generator context
   HttpClientContext httpClientContext;                      ///<HTTP client context
#if (SCEP_CLIENT_TLS_SUPPORT == ENABLED)
   ScepClientTlsInitCallback tlsInitCallback;                ///<TLS initialization callback function
#endif
   ScepClientCaCertVerifyCallback caCertVerifyCallback;      ///<CA certificate verification callback function
   ScepClientCsrGenCallback csrGenCallback;                  ///<CSR generation callback function
   ScepClientSelfSignedCertGenCallback selfSignedCertGenCallback; ///<Self-signed certificate generation callback function
   char_t serverName[SCEP_CLIENT_MAX_HOST_LEN + 1];          ///<Host name of the SCEP server
   uint16_t serverPort;                                      ///<TCP port number
   char_t uri[SCEP_CLIENT_MAX_URI_LEN + 1];                  ///<URI
   X509KeyType keyType;                                      ///<Public key type
#if (SCEP_CLIENT_RSA_SUPPORT == ENABLED)
   RsaPublicKey rsaPublicKey;                                ///<RSA public key
   RsaPrivateKey rsaPrivateKey;                              ///<RSA private key
#endif
   uint8_t csr[SCEP_CLIENT_MAX_CSR_LEN];                     ///<CSR
   size_t csrLen;                                            ///<Length of the CSR, in bytes
   uint8_t cert[SCEP_CLIENT_MAX_CERT_LEN];                   ///<Client's certificate
   size_t certLen;                                           ///<Length of the client's certificate, in bytes
   uint8_t caCert[SCEP_CLIENT_MAX_CA_CERT_LEN];              ///<CA certificate chain
   size_t caCertLen;                                         ///<Length of the CA certificate chain, in bytes
   uint_t caCaps;                                            ///<CA capabilities
   char_t transactionId[SCEP_CLIENT_TRANSACTION_ID_SIZE * 2 + 1]; ///<Transaction identifier
   uint8_t senderNonce[SCEP_NONCE_SIZE];                     ///<Sender nonce
   uint8_t buffer[SCEP_CLIENT_BUFFER_SIZE];                  ///<Memory buffer for input/output operations
   size_t bufferLen;                                         ///<Length of the buffer, in bytes
   size_t bufferPos;                                         ///<Current position in the buffer
   uint_t statusCode;                                        ///<HTTP status code
   char_t contentType[SCEP_CLIENT_MAX_CONTENT_TYPE_LEN + 1]; ///<Content type of the response
   uint_t failInfo;                                          ///<Failure reason
   SCEP_CLIENT_PRIVATE_CONTEXT                               ///<Application specific context
};


//SCEP client related functions
error_t scepClientInit(ScepClientContext *context);

#if (SCEP_CLIENT_TLS_SUPPORT == ENABLED)

error_t scepClientRegisterTlsInitCallback(ScepClientContext *context,
   ScepClientTlsInitCallback callback);

#endif

error_t scepClientRegisterCaCertVerifyCallback(ScepClientContext *context,
   ScepClientCaCertVerifyCallback callback);

error_t scepClientRegisterCsrGenCallback(ScepClientContext *context,
   ScepClientCsrGenCallback callback);

error_t scepClientRegisterSelfSignedCertGenCallback(ScepClientContext *context,
   ScepClientSelfSignedCertGenCallback callback);

error_t scepClientSetPrng(ScepClientContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t scepClientSetTimeout(ScepClientContext *context, systime_t timeout);

error_t scepClientSetHost(ScepClientContext *context, const char_t *host);
error_t scepClientSetUri(ScepClientContext *context, const char_t *uri);

error_t scepClientBindToInterface(ScepClientContext *context,
   NetInterface *interface);

error_t scepClientConnect(ScepClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t scepClientLoadKeyPair(ScepClientContext *context,
   const char_t *publicKey, size_t publicKeyLen, const char_t *privateKey,
   size_t privateKeyLen, const char_t *password);

void scepClientUnloadKeyPair(ScepClientContext *context);

error_t scepClientLoadCert(ScepClientContext *context,
   char_t *input, size_t length);

error_t scepClientStoreCert(ScepClientContext *context,
   char_t *output, size_t *written);

error_t scepClientLoadCaCert(ScepClientContext *context,
   char_t *input, size_t length);

error_t scepClientStoreCaCert(ScepClientContext *context,
   char_t *output, size_t *written);

error_t scepClientGetCaCaps(ScepClientContext *context, uint_t *caCaps);
error_t scepClientGetCaCert(ScepClientContext *context);
error_t scepClientEnroll(ScepClientContext *context);
error_t scepClientRenew(ScepClientContext *context);
error_t scepClientPoll(ScepClientContext *context);

ScepFailInfo scepClientGetFailInfo(ScepClientContext *context);

error_t scepClientDisconnect(ScepClientContext *context);
error_t scepClientClose(ScepClientContext *context);

void scepClientDeinit(ScepClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
