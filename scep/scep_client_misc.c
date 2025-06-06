/**
 * @file scep_client_misc.c
 * @brief Helper functions for SCEP client
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
#include "scep/scep_client_misc.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_create.h"
#include "pkix/x509_csr_parse.h"
#include "cipher/cipher_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Content encryption algorithm selection
 * @param[in] context Pointer to the SCEP client context
 * @param[out] contentEncrAlgo Content encryption algorithm
 * @return Error code
 **/

error_t scepClientSelectContentEncrAlgo(ScepClientContext *context,
   Pkcs7ContentEncrAlgo *contentEncrAlgo)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Clear contentEncryptionAlgorithm structure
   osMemset(contentEncrAlgo, 0, sizeof(Pkcs7ContentEncrAlgo));

#if (SCEP_CLIENT_AES_SUPPORT == ENABLED)
   //AES128-CBC encryption algorithm?
   if((context->caCaps & SCEP_CA_CAPS_AES) != 0)
   {
      //The client should use AES128-CBC in preference to triple DES-CBC if
      //it is supported by the CA (refer to RFC 8894, section 3.5.2)
      contentEncrAlgo->oid.value = AES128_CBC_OID;
      contentEncrAlgo->oid.length = sizeof(AES128_CBC_OID);
   }
   else
#endif
#if (SCEP_CLIENT_3DES_SUPPORT == ENABLED)
   //Triple DES-CBC encryption algorithm?
   if((context->caCaps & SCEP_CA_CAPS_DES3) != 0)
   {
      //CA supports the triple DES-CBC encryption algorithm
      contentEncrAlgo->oid.value = DES_EDE3_CBC_OID;
      contentEncrAlgo->oid.length = sizeof(DES_EDE3_CBC_OID);
   }
   else
#endif
   {
      //Report an error
      error = ERROR_UNSUPPORTED_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Signature algorithm selection
 * @param[in] context Pointer to the SCEP client context
 * @param[out] signatureAlgo Signature algorithm
 **/

error_t scepClientSelectSignatureAlgo(ScepClientContext *context,
   X509SignAlgoId *signatureAlgo)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Clear signatureValue structure
   osMemset(signatureAlgo, 0, sizeof(X509SignAlgoId));

#if (SCEP_CLIENT_RSA_SUPPORT == ENABLED)
   //RSA private key?
   if(context->keyType == X509_KEY_TYPE_RSA)
   {
#if (SCEP_CLIENT_SHA512_SUPPORT == ENABLED)
      //SHA-512 hashing algorithm?
      if((context->caCaps & SCEP_CA_CAPS_SHA512) != 0)
      {
         //CA supports the SHA-512 hashing algorithm
         signatureAlgo->oid.value = SHA512_WITH_RSA_ENCRYPTION_OID;
         signatureAlgo->oid.length = sizeof(SHA512_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
#if (SCEP_CLIENT_SHA256_SUPPORT == ENABLED)
      //SHA-256 hashing algorithm?
      if((context->caCaps & SCEP_CA_CAPS_SHA256) != 0)
      {
         //The client should use SHA-256 in preference to SHA-1 hashing if they
         //are supported by the CA (refer to RFC 8894, section 3.5.2)
         signatureAlgo->oid.value = SHA256_WITH_RSA_ENCRYPTION_OID;
         signatureAlgo->oid.length = sizeof(SHA256_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
#if (SCEP_CLIENT_SHA1_SUPPORT == ENABLED)
      //SHA-1 hashing algorithm?
      if((context->caCaps & SCEP_CA_CAPS_SHA1) != 0)
      {
         //CA supports the SHA-1 hashing algorithm
         signatureAlgo->oid.value = SHA1_WITH_RSA_ENCRYPTION_OID;
         signatureAlgo->oid.length = sizeof(SHA1_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
      {
         //Report an error
         error = ERROR_UNSUPPORTED_ALGO;
      }
   }
   else
#endif
   //Invalid private key?
   {
      //Report an error
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse CA certificate
 * @param[in] context Pointer to the SCEP client context
 * @param[out] certInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t scepClientParseCaCert(ScepClientContext *context,
   X509CertInfo *certInfo)
{
   error_t error;
   size_t length;
   const uint8_t *data;

   //Initialize status code
   error = NO_ERROR;

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
         error = x509ParseCertificate(data, length, certInfo);

         //Check status code
         if(!error)
         {
            //Next certificate
            data += certInfo->raw.length;
            length -= certInfo->raw.length;
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
 * @brief Verify CA certificate
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientVerifyCaCert(ScepClientContext *context)
{
   error_t error;
   time_t currentTime;
   X509CertInfo *certInfo;

   //Any registered callback?
   if(context->caCertVerifyCallback != NULL)
   {
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
            //Retrieve current time
            currentTime = getCurrentUnixTime();

            //Any real-time clock implemented?
            if(currentTime != 0)
            {
               DateTime currentDate;
               const X509Validity *validity;

               //Convert Unix timestamp to date
               convertUnixTimeToDate(currentTime, &currentDate);

               //The certificate validity period is the time interval during which
               //the CA warrants that it will maintain information about the status
               //of the certificate
               validity = &certInfo->tbsCert.validity;

               //Check the validity period
               if(compareDateTime(&currentDate, &validity->notBefore) < 0 ||
                  compareDateTime(&currentDate, &validity->notAfter) > 0)
               {
                  //The certificate has expired or is not yet valid
                  error = ERROR_CERTIFICATE_EXPIRED;
               }
            }
         }

         //Check status code
         if(!error)
         {
            //After the client gets the CA certificate, it should authenticate it.
            //For example, the client could compare the certificate's fingerprint
            //with locally configured, out-of-band distributed, identifying
            //information, or by some equivalent means such as a direct comparison
            //with a locally stored copy of the certificate
            error = context->caCertVerifyCallback(context, certInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(certInfo);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Invalid CA certificate?
   if(error)
   {
      //Clear CA certificate
      context->caCertLen = 0;
   }

   //Return status code
   return error;
}


/**
 * @brief Transaction identifier generation
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientGenerateTransactionId(ScepClientContext *context)
{
   error_t error;
   size_t i;
   uint8_t buffer[SCEP_CLIENT_TRANSACTION_ID_SIZE];

   //Hex conversion table
   static const char_t hexDigit[16] =
   {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
   };

   //The transactionID must be unique, but not necessarily randomly generated
   //(refer to RFC 8894, section 3.2.1.1)
   error = context->prngAlgo->generate(context->prngContext, buffer,
      SCEP_CLIENT_TRANSACTION_ID_SIZE);

   //Check status code
   if(!error)
   {
      //The transaction identifier must be encoded as a PrintableString
      for(i = 0; i < SCEP_CLIENT_TRANSACTION_ID_SIZE; i++)
      {
         //Convert upper nibble
         context->transactionId[i * 2] = hexDigit[(buffer[i] >> 4) & 0x0F];
         //Then convert lower nibble
         context->transactionId[i * 2 + 1] = hexDigit[buffer[i] & 0x0F];
      }

      //Properly terminate the string with a NULL character
      context->transactionId[i * 2] = '\0';
   }

   //Return status code
   return error;
}


/**
 * @brief Generate PKCS #10 certificate request
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientGenerateCsr(ScepClientContext *context)
{
   error_t error;

   //Any registered callback?
   if(context->csrGenCallback != NULL)
   {
      //Generate PKCS #10 certificate request
      error = context->csrGenCallback(context, context->csr,
         SCEP_CLIENT_MAX_CSR_LEN, &context->csrLen);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_CSR;
   }

   //Return status code
   return error;
}


/**
 * @brief Generate self-signed certificate
 * @param[in] context Pointer to the SCEP client context
 * @return Error code
 **/

error_t scepClientGenerateSelfSignedCert(ScepClientContext *context)
{
   error_t error;

   //Any registered callback?
   if(context->selfSignedCertGenCallback != NULL)
   {
      //Generate self-signed X.509 certificate
      error = context->selfSignedCertGenCallback(context, context->cert,
         SCEP_CLIENT_MAX_CERT_LEN, &context->certLen);
   }
   else
   {
      time_t currentTime;
      X509CsrInfo *csrInfo;
      X509Extensions *extensions;
      X509Validity validity;

      //Debug message
      TRACE_INFO("Generating self-signed certificate...\r\n");

      //Allocate a memory buffer to hold CSR info
      csrInfo = cryptoAllocMem(sizeof(X509CsrInfo));

      //Successful memory allocation?
      if(csrInfo != NULL)
      {
         //The self-signed certificate should use the same subject name and key as
         //in the PKCS #10 request (refer to RFC 8894, section 2.3)
         error = x509ParseCsr(context->csr, context->csrLen, csrInfo);

         //Check status code
         if(!error)
         {
            //Clear CSR attributes
            osMemset(&csrInfo->certReqInfo.attributes, 0, sizeof(X509Attributes));

            //Point to the certificate extensions
            extensions = &csrInfo->certReqInfo.attributes.extensionReq;

            //The cA boolean indicates whether the certified public key may be
            //used to verify certificate signatures
            extensions->basicConstraints.critical = TRUE;
            extensions->basicConstraints.cA = FALSE;
            extensions->basicConstraints.pathLenConstraint = -1;

            //The keyUsage extension in the certificate must indicate that it is
            //valid for digitalSignature and keyEncipherment (refer to RFC 8894,
            //section 2.3)
            extensions->keyUsage.critical = TRUE;
            extensions->keyUsage.bitmap = X509_KEY_USAGE_DIGITAL_SIGNATURE |
               X509_KEY_USAGE_KEY_ENCIPHERMENT;

            //Retrieve current time
            currentTime = getCurrentUnixTime();

            //Any real-time clock implemented?
            if(currentTime != 0)
            {
               //Validity period
               convertUnixTimeToDate(currentTime, &validity.notBefore);
               convertUnixTimeToDate(currentTime + 86400, &validity.notAfter);
            }
            else
            {
               //Validity period
               validity.notBefore.year = 2020;
               validity.notBefore.month = 1;
               validity.notBefore.day = 1;
               validity.notBefore.hours = 12;
               validity.notBefore.minutes = 0;
               validity.notBefore.seconds = 0;
               validity.notAfter.year = 2021;
               validity.notAfter.month = 1;
               validity.notAfter.day = 1;
               validity.notAfter.hours = 12;
               validity.notAfter.minutes = 0;
               validity.notAfter.seconds = 0;
            }

            //Create a self-signed X.509 certificate
            error = x509CreateCertificate(context->prngAlgo, context->prngContext,
               &csrInfo->certReqInfo, &context->rsaPublicKey, NULL, NULL, &validity,
               &csrInfo->signatureAlgo, &context->rsaPrivateKey, context->cert,
               &context->certLen);
         }

         //Release previously allocated memory
         cryptoFreeMem(csrInfo);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
}

#endif
