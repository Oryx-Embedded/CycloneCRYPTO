/**
 * @file scep_client.c
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
 * @section Description
 *
 * SCEP is a protocol used to determine the current status of a digital
 * certificate without requiring CRLs. Refer to the following RFCs for
 * complete details:
 * - RFC 6960: X.509 Internet Public Key Infrastructure SCEP
 * - RFC 8954: Online Certificate Status Protocol (SCEP) Nonce Extension
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL SCEP_TRACE_LEVEL

//Dependencies
#include "scep/scep_client.h"
#include "scep/scep_client_operations.h"
#include "scep/scep_client_misc.h"
#include "pkix/pem_import.h"
#include "pkix/pem_key_import.h"
#include "pkix/pem_export.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief SCEP client initialization
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientInit(ScepClientContext *context)
{
   error_t error;

   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Initializing SCEP client...\r\n");

   //Initialize context
   osMemset(context, 0, sizeof(ScepClientContext));

   //Initialize HTTP client context
   error = httpClientInit(&context->httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //Initialize SCEP client state
   context->state = SCEP_CLIENT_STATE_DISCONNECTED;

   //Default timeout
   context->timeout = SCEP_CLIENT_DEFAULT_TIMEOUT;
   //Default URI
   osStrcpy(context->uri, "/");

   //Successful initialization
   return NO_ERROR;
}


#if (SCEP_CLIENT_TLS_SUPPORT == ENABLED)

/**
 * @brief Register TLS initialization callback function
 * @param[in] context Pointer to the SCEP client context
 * @param[in] callback TLS initialization callback function
 * @return Error code
 **/

error_t scepClientRegisterTlsInitCallback(ScepClientContext *context,
   ScepClientTlsInitCallback callback)
{
   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->tlsInitCallback = callback;

   //Successful processing
   return NO_ERROR;
}

#endif


/**
 * @brief Register CA certificate verification callback function
 * @param[in] context Pointer to the SCEP client context
 * @param[in] callback CA certificate verification callback function
 * @return Error code
 **/

error_t scepClientRegisterCaCertVerifyCallback(ScepClientContext *context,
   ScepClientCaCertVerifyCallback callback)
{
   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->caCertVerifyCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register CSR generation callback function
 * @param[in] context Pointer to the SCEP client context
 * @param[in] callback CSR generation callback function
 * @return Error code
 **/

error_t scepClientRegisterCsrGenCallback(ScepClientContext *context,
   ScepClientCsrGenCallback callback)
{
   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->csrGenCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register self-signed certificate generation callback function
 * @param[in] context Pointer to the SCEP client context
 * @param[in] callback Self-signed certificate generation callback function
 * @return Error code
 **/

error_t scepClientRegisterSelfSignedCertGenCallback(ScepClientContext *context,
   ScepClientSelfSignedCertGenCallback callback)
{
   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->selfSignedCertGenCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the pseudo-random number generator to be used
 * @param[in] context Pointer to the SCEP client context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t scepClientSetPrng(ScepClientContext *context, const PrngAlgo *prngAlgo,
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
 * @param[in] context Pointer to the SCEP client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t scepClientSetTimeout(ScepClientContext *context, systime_t timeout)
{
   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the domain name of the SCEP server
 * @param[in] context Pointer to the SCEP client context
 * @param[in] host NULL-terminated string containing the host name
 * @return Error code
 **/

error_t scepClientSetHost(ScepClientContext *context, const char_t *host)
{
   //Check parameters
   if(context == NULL || host == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the host name is acceptable
   if(osStrlen(host) > SCEP_CLIENT_MAX_HOST_LEN)
      return ERROR_INVALID_LENGTH;

   //Save host name
   osStrcpy(context->serverName, host);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set request URI
 * @param[in] context Pointer to the SCEP client context
 * @param[in] uri NULL-terminated string that contains the resource name
 * @return Error code
 **/

error_t scepClientSetUri(ScepClientContext *context, const char_t *uri)
{
   //Check parameters
   if(context == NULL || uri == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the URI is acceptable
   if(osStrlen(uri) > SCEP_CLIENT_MAX_URI_LEN)
      return ERROR_INVALID_LENGTH;

   //Save the URI of the directory object
   osStrcpy(context->uri, uri);

   //Successful processing
   return NO_ERROR;
}

/**
 * @brief Bind the SCEP client to a particular network interface
 * @param[in] context Pointer to the SCEP client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t scepClientBindToInterface(ScepClientContext *context,
   NetInterface *interface)
{
   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the SCEP client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the address of the SCEP server
 * @param[in] context Pointer to the SCEP client context
 * @param[in] serverIpAddr IP address of the SCEP server to connect to
 * @param[in] serverPort UDP port number
 * @return Error code
 **/

error_t scepClientConnect(ScepClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;

   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Establish connection with the HTTP server
   while(!error)
   {
      //Check SCEP client state
      if(context->state == SCEP_CLIENT_STATE_DISCONNECTED)
      {
         //Save the TCP port number to be used
         context->serverPort = serverPort;

#if (SCEP_CLIENT_TLS_SUPPORT == ENABLED)
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
            context->state = SCEP_CLIENT_STATE_CONNECTING;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_CONNECTING)
      {
         //Establish HTTP connection
         error = httpClientConnect(&context->httpClientContext, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //The HTTP connection is established
            context->state = SCEP_CLIENT_STATE_CONNECTED;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_CONNECTED)
      {
         //The client is connected to the SCEP server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the SCEP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      httpClientClose(&context->httpClientContext);
      //Update SCEP client state
      context->state = SCEP_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Load public/private key pair
 * @param[in] context Pointer to the SCEP client context
 * @param[in] publicKey Public key (PEM format)
 * @param[in] publicKeyLen Length of the public key
 * @param[in] privateKey Private key (PEM format)
 * @param[in] privateKeyLen Length of the private key
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t scepClientLoadKeyPair(ScepClientContext *context,
   const char_t *publicKey, size_t publicKeyLen, const char_t *privateKey,
   size_t privateKeyLen, const char_t *password)
{
   error_t error;
   X509KeyType type;

   //Check parameters
   if(context == NULL || publicKey == NULL || publicKeyLen == 0 ||
      privateKey == NULL || privateKeyLen == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Release the current key pair, if any
   scepClientUnloadKeyPair(context);

   //Extract the type of the public key
   type = pemGetPublicKeyType(publicKey, publicKeyLen);

#if (SCEP_CLIENT_RSA_SUPPORT == ENABLED)
   //RSA public key?
   if(type == X509_KEY_TYPE_RSA)
   {
      //Save public key type
      context->keyType = X509_KEY_TYPE_RSA;

      //Initialize RSA public and private keys
      rsaInitPublicKey(&context->rsaPublicKey);
      rsaInitPrivateKey(&context->rsaPrivateKey);

      //Decode the PEM file that contains the RSA public key
      error = pemImportRsaPublicKey(&context->rsaPublicKey, publicKey,
         publicKeyLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the RSA private key
         error = pemImportRsaPrivateKey(&context->rsaPrivateKey, privateKey,
            privateKeyLen, password);
      }
   }
   else
#endif
   //Invalid public key?
   {
      //The supplied public key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      scepClientUnloadKeyPair(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Unload public/private key pair
 * @param[in] context Pointer to the SCEP client context
 **/

void scepClientUnloadKeyPair(ScepClientContext *context)
{
   //Make sure the SCEP client context is valid
   if(context != NULL)
   {
#if (SCEP_CLIENT_RSA_SUPPORT == ENABLED)
      //RSA key pair?
      if(context->keyType == X509_KEY_TYPE_RSA)
      {
         //Release RSA public and private keys
         rsaFreePublicKey(&context->rsaPublicKey);
         rsaFreePrivateKey(&context->rsaPrivateKey);
      }
      else
#endif
      //Invalid key pair?
      {
         //Just for sanity
      }
   }
}


/**
 * @brief Load client's certificate
 * @param[in] context Pointer to the SCEP client context
 * @param[out] input Pointer to the PEM-encoded certificate
 * @param[out] length Length of the PEM-encoded certificate
 * @return Error code
 **/

error_t scepClientLoadCert(ScepClientContext *context,
   char_t *input, size_t length)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the SCEP client context is valid
   if(context != NULL)
   {
      //Valid certificate?
      if(input != NULL && length > 0)
      {
         //The first pass calculates the length of the DER-encoded certificate
         error = pemImportCertificate(input, length, NULL, &n, NULL);

         //Check status code
         if(!error)
         {
            //Check the length of the certificate
            if(n <= SCEP_CLIENT_MAX_CERT_LEN)
            {
               //The second pass decodes the PEM certificate
               error = pemImportCertificate(input, length, context->cert,
                  &context->certLen, NULL);
            }
            else
            {
               //Report an error
               error = ERROR_INVALID_LENGTH;
            }
         }
      }
      else
      {
         //Clear certificate
         context->certLen = 0;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Store client's certificate
 * @param[in] context Pointer to the SCEP client context
 * @param[out] output Pointer to the buffer where to store the PEM-encoded
 *   certificate (optional parameter)
 * @param[out] written Actual length of the certificate, in bytes
 * @return Error code
 **/

error_t scepClientStoreCert(ScepClientContext *context,
   char_t *output, size_t *written)
{
   error_t error;

   //Check parameters
   if(context == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Valid certificate?
   if(context->certLen > 0)
   {
      //Export the certificate to PEM format
      error = pemExportCertificate(context->cert, context->certLen, output,
         written);
   }
   else
   {
      //Report an error
      error = ERROR_NO_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Load out of band CA certificate
 * @param[in] context Pointer to the SCEP client context
 * @param[out] input Pointer to the PEM-encoded CA certificate
 * @param[out] length Length of the PEM-encoded CA certificate
 * @return Error code
 **/

error_t scepClientLoadCaCert(ScepClientContext *context,
   char_t *input, size_t length)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the SCEP client context is valid
   if(context != NULL)
   {
      //Valid certificate?
      if(input != NULL && length > 0)
      {
         //The first pass calculates the length of the DER-encoded certificate
         error = pemImportCertificate(input, length, NULL, &n, NULL);

         //Check status code
         if(!error)
         {
            //Check the length of the CA certificate
            if(n <= SCEP_CLIENT_MAX_CA_CERT_LEN)
            {
               //The second pass decodes the PEM certificate
               error = pemImportCertificate(input, length, context->caCert,
                  &context->caCertLen, NULL);
            }
            else
            {
               //Report an error
               error = ERROR_INVALID_LENGTH;
            }
         }
      }
      else
      {
         //Clear CA certificate
         context->caCertLen = 0;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Store CA certificate
 * @param[in] context Pointer to the SCEP client context
 * @param[out] output Pointer to the buffer where to store the PEM-encoded
 *   CA certificate (optional parameter)
 * @param[out] written Actual length of the CA certificate, in bytes
 * @return Error code
 **/

error_t scepClientStoreCaCert(ScepClientContext *context,
   char_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *data;
   Asn1Tag tag;

   //Check parameters
   if(context == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Total number of bytes that have been written
   *written = 0;

   //Valid CA certificate chain?
   if(context->caCertLen > 0)
   {
      //Point to the first certificate of the chain
      data = context->caCert;
      length = context->caCertLen;

      //The intermediate CA certificate is the leaf certificate
      while(length > 0 && !error)
      {
         //Parse certificate
         error = asn1ReadSequence(data, length, &tag);

         //Check status code
         if(!error)
         {
            //Export the certificate to PEM format
            error = pemExportCertificate(data, tag.totalLength, output, &n);
         }

         //Check status code
         if(!error)
         {
            //Next DER certificate
            data += tag.totalLength;
            length -= tag.totalLength;

            //Next PEM certificate
            ASN1_INC_POINTER(output, n);
            *written += n;
         }
      }
   }
   else
   {
      //Report an error
      error = ERROR_NO_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Request capabilities from a CA
 * @param[in] context Pointer to the SCEP client context
 * @param[out] caCaps List of CA capabilities
 * @return Error code
 **/

error_t scepClientGetCaCaps(ScepClientContext *context, uint_t *caCaps)
{
   error_t error;

   //Check parameters
   if(context == NULL || caCaps == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check SCEP client state
      if(context->state == SCEP_CLIENT_STATE_CONNECTED ||
         context->state == SCEP_CLIENT_STATE_CERT_POLL)
      {
         //Update SCEP client state
         context->state = SCEP_CLIENT_STATE_GET_CA_CAPS;
      }
      else if(context->state == SCEP_CLIENT_STATE_GET_CA_CAPS)
      {
         //Perform GetCACaps operation
         error = scepClientSendGetCaCaps(context);

         //Check status code
         if(!error)
         {
            //Return CA capabilities
            *caCaps = context->caCaps;

            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = SCEP_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Get CA certificate
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientGetCaCert(ScepClientContext *context)
{
   error_t error;

   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check SCEP client state
      if(context->state == SCEP_CLIENT_STATE_CONNECTED ||
         context->state == SCEP_CLIENT_STATE_CERT_POLL)
      {
         //Update SCEP client state
         context->state = SCEP_CLIENT_STATE_GET_CA;
      }
      else if(context->state == SCEP_CLIENT_STATE_GET_CA)
      {
         //Perform GetCACert operation
         error = scepClientSendGetCaCert(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = SCEP_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Certificate enrollment
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientEnroll(ScepClientContext *context)
{
   error_t error;

   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check SCEP client state
      if(context->state == SCEP_CLIENT_STATE_CONNECTED ||
         context->state == SCEP_CLIENT_STATE_CERT_POLL)
      {
         //Update SCEP client state
         context->state = SCEP_CLIENT_STATE_GET_CA;
      }
      else if(context->state == SCEP_CLIENT_STATE_GET_CA)
      {
         //If the CA certificate(s) have not previously been acquired by the
         //client through some other means, the client must retrieve them before
         //any PKI operation can be started (refer to RFC 8894, section 2.2)
         if(context->caCertLen == 0)
         {
            //Perform GetCACert operation
            error = scepClientSendGetCaCert(context);
         }

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_GET_CA_CAPS;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_GET_CA_CAPS)
      {
         //In order to provide support for future enhancements to the protocol,
         //CAs must implement the GetCACaps message to allow clients to query
         //which functionality is available from the CA (refer to RFC 8894,
         //section 3.5)
         if(context->caCaps == 0)
         {
            //Perform GetCACaps operation
            error = scepClientSendGetCaCaps(context);
         }

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_CSR_GEN;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_CSR_GEN)
      {
         //Generate PKCS #10 certificate request
         error = scepClientGenerateCsr(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_SELF_SIGNED_CERT_GEN;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_SELF_SIGNED_CERT_GEN)
      {
         //If the client does not have an appropriate existing certificate, then
         //a locally generated self-signed certificate must be used (refer to
         //RFC 8894, section 2.3)
         error = scepClientGenerateSelfSignedCert(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_TRANSACTION_ID_GEN;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_TRANSACTION_ID_GEN)
      {
         //The client must use a unique string as the transaction identifier,
         //encoded as a PrintableString, which must be used for all PKI messages
         //exchanged for a given operation, such as a certificate issue (refer
         //to RFC 8894, section 3.2.1.1)
         error = scepClientGenerateTransactionId(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_PKCS_REQ;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_PKCS_REQ)
      {
         //Perform PKCSReq operation
         error = scepClientSendPkcsReq(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE || error == ERROR_REQUEST_REJECTED)
   {
      //Revert to default state
      context->state = SCEP_CLIENT_STATE_CONNECTED;
   }
   else if(error == ERROR_REQUEST_PENDING)
   {
      //If the CA is configured to manually authenticate the client, a CertRep
      //PENDING message may be returned
      context->state = SCEP_CLIENT_STATE_CERT_POLL;
   }
   else
   {
      //Just for sanity
   }

   //Return status code
   return error;
}


/**
 * @brief Certificate renewal
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientRenew(ScepClientContext *context)
{
   error_t error;

   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the previously issued certificate is valid
   if(context->certLen == 0)
      return ERROR_BAD_CERTIFICATE;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check SCEP client state
      if(context->state == SCEP_CLIENT_STATE_CONNECTED ||
         context->state == SCEP_CLIENT_STATE_CERT_POLL)
      {
         //Update SCEP client state
         context->state = SCEP_CLIENT_STATE_GET_CA;
      }
      else if(context->state == SCEP_CLIENT_STATE_GET_CA)
      {
         //If the CA certificate(s) have not previously been acquired by the
         //client through some other means, the client must retrieve them before
         //any PKI operation can be started (refer to RFC 8894, section 2.2)
         if(context->caCertLen == 0)
         {
            //Perform GetCACert operation
            error = scepClientSendGetCaCert(context);
         }

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_GET_CA_CAPS;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_GET_CA_CAPS)
      {
         //In order to provide support for future enhancements to the protocol,
         //CAs must implement the GetCACaps message to allow clients to query
         //which functionality is available from the CA (refer to RFC 8894,
         //section 3.5)
         if(context->caCaps == 0)
         {
            //Perform GetCACaps operation
            error = scepClientSendGetCaCaps(context);
         }

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_CSR_GEN;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_CSR_GEN)
      {
         //Generate PKCS #10 certificate request
         error = scepClientGenerateCsr(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_TRANSACTION_ID_GEN;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_TRANSACTION_ID_GEN)
      {
         //The client must use a unique string as the transaction identifier,
         //encoded as a PrintableString, which must be used for all PKI messages
         //exchanged for a given operation, such as a certificate issue (refer
         //to RFC 8894, section 3.2.1.1)
         error = scepClientGenerateTransactionId(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_RENEWAL_REQ;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_RENEWAL_REQ)
      {
         //Perform RenewalReq operation
         error = scepClientSendRenewalReq(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE || error == ERROR_REQUEST_REJECTED)
   {
      //Revert to default state
      context->state = SCEP_CLIENT_STATE_CONNECTED;
   }
   else if(error == ERROR_REQUEST_PENDING)
   {
      //If the CA is configured to manually authenticate the client, a CertRep
      //PENDING message may be returned
      context->state = SCEP_CLIENT_STATE_CERT_POLL;
   }
   else
   {
      //Just for sanity
   }

   //Return status code
   return error;
}


/**
 * @brief Certificate polling
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientPoll(ScepClientContext *context)
{
   error_t error;

   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check SCEP client state
      if(context->state == SCEP_CLIENT_STATE_CERT_POLL)
      {
         //Perform CertPoll operation
         error = scepClientSendCertPoll(context);

         //Check status code
         if(!error)
         {
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE || error == ERROR_REQUEST_REJECTED)
   {
      //Revert to default state
      context->state = SCEP_CLIENT_STATE_CONNECTED;
   }
   else if(error == ERROR_REQUEST_PENDING)
   {
      //If the CA is configured to manually authenticate the client, a CertRep
      //PENDING message may be returned
      context->state = SCEP_CLIENT_STATE_CERT_POLL;
   }
   else
   {
      //Just for sanity
   }

   //Return status code
   return error;
}


/**
 * @brief Get failure reason
 * @param[in] context Pointer to the SCEP client context
 * @return Failure reason
 **/

ScepFailInfo scepClientGetFailInfo(ScepClientContext *context)
{
   ScepFailInfo failInfo;

   //Make sure the SCEP client context is valid
   if(context != NULL)
   {
      failInfo = (ScepFailInfo) context->failInfo;
   }
   else
   {
      failInfo = (ScepFailInfo) 0;
   }

   //Return the value of the failInfo attribute
   return failInfo;
}


/**
 * @brief Gracefully disconnect from the SCEP server
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientDisconnect(ScepClientContext *context)
{
   error_t error;

   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the SCEP server
   while(!error)
   {
      //Check SCEP client state
      if(context->state == SCEP_CLIENT_STATE_CONNECTED)
      {
         //Gracefully shutdown HTTP connection
         context->state = SCEP_CLIENT_STATE_DISCONNECTING;
      }
      else if(context->state == SCEP_CLIENT_STATE_DISCONNECTING)
      {
         //Gracefully shutdown HTTP connection
         error = httpClientDisconnect(&context->httpClientContext);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close HTTP connection
            httpClientClose(&context->httpClientContext);
            //Update SCEP client state
            context->state = SCEP_CLIENT_STATE_DISCONNECTED;
         }
      }
      else if(context->state == SCEP_CLIENT_STATE_DISCONNECTED)
      {
         //The client is disconnected from the SCEP server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to gracefully disconnect from the SCEP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close HTTP connection
      httpClientClose(&context->httpClientContext);
      //Update SCEP client state
      context->state = SCEP_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the SCEP server
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientClose(ScepClientContext *context)
{
   //Make sure the SCEP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close HTTP connection
   httpClientClose(&context->httpClientContext);
   //Update SCEP client state
   context->state = SCEP_CLIENT_STATE_DISCONNECTED;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release SCEP client context
 * @param[in] context Pointer to the SCEP client context
 **/

void scepClientDeinit(ScepClientContext *context)
{
   //Make sure the SCEP client context is valid
   if(context != NULL)
   {
      //Release HTTP client context
      httpClientDeinit(&context->httpClientContext);

      //Release public/private key pair
      scepClientUnloadKeyPair(context);

      //Clear SCEP client context
      osMemset(context, 0, sizeof(ScepClientContext));
   }
}

#endif
