/**
 * @file pem_cert_key_import.c
 * @brief PEM certificate public key import functions
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
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkix/pem_import.h"
#include "pkix/pem_cert_key_import.h"
#include "pkix/pem_decrypt.h"
#include "pkix/pkcs5_decrypt.h"
#include "pkix/pkcs8_key_parse.h"
#include "pkix/x509_key_parse.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Extract the RSA public key from a PEM certificate
 * @param[out] publicKey RSA public key resulting from the parsing process
 * @param[in] input Pointer to the PEM certificate
 * @param[in] length Length of the PEM certificate
 * @return Error code
 **/

error_t pemImportRsaCertPublicKey(RsaPublicKey *publicKey, const char_t *input,
   size_t length)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertInfo *certInfo;

   //The first pass calculates the length of the DER-encoded certificate
   error = pemImportCertificate(input, length, NULL, &derCertLen,
      NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = cryptoAllocMem(derCertLen);

      //Successful memory allocation?
      if(derCert != NULL)
      {
         //The second pass decodes the PEM certificate
         error = pemImportCertificate(input, length, derCert, &derCertLen,
            NULL);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = cryptoAllocMem(sizeof(X509CertInfo));

            //Successful memory allocation?
            if(certInfo != NULL)
            {
               X509Options options;

               //Additional certificate parsing options
               options = X509_DEFAULT_OPTIONS;
               options.ignoreUnknownExtensions = TRUE;

               //Parse X.509 certificate
               error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
                  &options);

               //Check status code
               if(!error)
               {
                  //Import the RSA public key
                  error = x509ImportRsaPublicKey(publicKey,
                     &certInfo->tbsCert.subjectPublicKeyInfo);
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

         //Release previously allocated memory
         cryptoFreeMem(derCert);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract the DSA public key from a PEM certificate
 * @param[out] publicKey DSA public key resulting from the parsing process
 * @param[in] input Pointer to the PEM certificate
 * @param[in] length Length of the PEM certificate
 * @return Error code
 **/

error_t pemImportDsaCertPublicKey(DsaPublicKey *publicKey, const char_t *input,
   size_t length)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertInfo *certInfo;

   //The first pass calculates the length of the DER-encoded certificate
   error = pemImportCertificate(input, length, NULL, &derCertLen,
      NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = cryptoAllocMem(derCertLen);

      //Successful memory allocation?
      if(derCert != NULL)
      {
         //The second pass decodes the PEM certificate
         error = pemImportCertificate(input, length, derCert, &derCertLen,
            NULL);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = cryptoAllocMem(sizeof(X509CertInfo));

            //Successful memory allocation?
            if(certInfo != NULL)
            {
               X509Options options;

               //Additional certificate parsing options
               options = X509_DEFAULT_OPTIONS;
               options.ignoreUnknownExtensions = TRUE;

               //Parse X.509 certificate
               error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
                  &options);

               //Check status code
               if(!error)
               {
                  //Import the DSA public key
                  error = x509ImportDsaPublicKey(publicKey,
                     &certInfo->tbsCert.subjectPublicKeyInfo);
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

         //Release previously allocated memory
         cryptoFreeMem(derCert);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract the EC public key from a PEM certificate
 * @param[out] publicKey EC public key resulting from the parsing process
 * @param[in] input Pointer to the PEM certificate
 * @param[in] length Length of the PEM certificate
 * @return Error code
 **/

error_t pemImportEcCertPublicKey(EcPublicKey *publicKey, const char_t *input,
   size_t length)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertInfo *certInfo;

   //The first pass calculates the length of the DER-encoded certificate
   error = pemImportCertificate(input, length, NULL, &derCertLen,
      NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = cryptoAllocMem(derCertLen);

      //Successful memory allocation?
      if(derCert != NULL)
      {
         //The second pass decodes the PEM certificate
         error = pemImportCertificate(input, length, derCert, &derCertLen,
            NULL);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = cryptoAllocMem(sizeof(X509CertInfo));

            //Successful memory allocation?
            if(certInfo != NULL)
            {
               X509Options options;

               //Additional certificate parsing options
               options = X509_DEFAULT_OPTIONS;
               options.ignoreUnknownExtensions = TRUE;

               //Parse X.509 certificate
               error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
                  &options);

               //Check status code
               if(!error)
               {
                  //Import the EC public key
                  error = x509ImportEcPublicKey(publicKey,
                     &certInfo->tbsCert.subjectPublicKeyInfo);
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

         //Release previously allocated memory
         cryptoFreeMem(derCert);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract the EdDSA public key from a PEM certificate
 * @param[out] publicKey EdDSA public key resulting from the parsing process
 * @param[in] input Pointer to the PEM certificate
 * @param[in] length Length of the PEM certificate
 * @return Error code
 **/

error_t pemImportEddsaCertPublicKey(EddsaPublicKey *publicKey,
   const char_t *input, size_t length)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertInfo *certInfo;

   //The first pass calculates the length of the DER-encoded certificate
   error = pemImportCertificate(input, length, NULL, &derCertLen,
      NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = cryptoAllocMem(derCertLen);

      //Successful memory allocation?
      if(derCert != NULL)
      {
         //The second pass decodes the PEM certificate
         error = pemImportCertificate(input, length, derCert, &derCertLen,
            NULL);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = cryptoAllocMem(sizeof(X509CertInfo));

            //Successful memory allocation?
            if(certInfo != NULL)
            {
               X509Options options;

               //Additional certificate parsing options
               options = X509_DEFAULT_OPTIONS;
               options.ignoreUnknownExtensions = TRUE;

               //Parse X.509 certificate
               error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
                  &options);

               //Check status code
               if(!error)
               {
                  //Import the EdDSA public key
                  error = x509ImportEddsaPublicKey(publicKey,
                     &certInfo->tbsCert.subjectPublicKeyInfo);
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

         //Release previously allocated memory
         cryptoFreeMem(derCert);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract the type of the public key contained in a PEM certificate
 * @param[in] input Pointer to the PEM certificate
 * @param[in] length Length of the PEM certificate
 * @return Public key type
 **/

X509KeyType pemGetCertPublicKeyType(const char_t *input, size_t length)
{
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   X509KeyType keyType;
   X509CertInfo *certInfo;
   size_t oidLen;
   const uint8_t *oid;

   //Initialize variable
   keyType = X509_KEY_TYPE_UNKNOWN;

   //The first pass calculates the length of the DER-encoded certificate
   error = pemImportCertificate(input, length, NULL, &derCertLen,
      NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = cryptoAllocMem(derCertLen);

      //Successful memory allocation?
      if(derCert != NULL)
      {
         //The second pass decodes the PEM certificate
         error = pemImportCertificate(input, length, derCert, &derCertLen,
            NULL);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = cryptoAllocMem(sizeof(X509CertInfo));

            //Successful memory allocation?
            if(certInfo != NULL)
            {
               X509Options options;

               //Additional certificate parsing options
               options = X509_DEFAULT_OPTIONS;
               options.ignoreUnknownExtensions = TRUE;

               //Parse X.509 certificate
               error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
                  &options);

               //Check status code
               if(!error)
               {
                  //Point to the public key identifier
                  oid = certInfo->tbsCert.subjectPublicKeyInfo.oid.value;
                  oidLen = certInfo->tbsCert.subjectPublicKeyInfo.oid.length;

                  //Get the public key type that matches the specified OID
                  keyType = x509GetPublicKeyType(oid, oidLen);
               }

               //Release previously allocated memory
               cryptoFreeMem(certInfo);
            }
         }

         //Release previously allocated memory
         cryptoFreeMem(derCert);
      }
   }

   //Return the public key type
   return keyType;
}

#endif
