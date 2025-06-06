/**
 * @file pem_key_import.c
 * @brief PEM key file import functions
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
#include "pkix/pem_key_import.h"
#include "pkix/pem_decrypt.h"
#include "pkix/pkcs5_decrypt.h"
#include "pkix/pkcs8_key_parse.h"
#include "pkix/x509_key_parse.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Decode a PEM file containing an RSA public key
 * @param[out] publicKey RSA public key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @return Error code
 **/

error_t pemImportRsaPublicKey(RsaPublicKey *publicKey, const char_t *input,
   size_t length)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(publicKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "RSA PUBLIC KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "RSA PUBLIC KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read RSAPublicKey structure
            error = x509ParseRsaPublicKey(buffer, n, &publicKeyInfo.rsaPublicKey);
         }

         //Check status code
         if(!error)
         {
            //Set public key algorithm identifier
            publicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
            publicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

            //Import the RSA public key
            error = x509ImportRsaPublicKey(publicKey, &publicKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the RSA public key
            error = x509ImportRsaPublicKey(publicKey, &publicKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //The PEM file does not contain a valid public key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing an RSA private key
 * @param[out] privateKey RSA private key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t pemImportRsaPrivateKey(RsaPrivateKey *privateKey, const char_t *input,
   size_t length, const char_t *password)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   PemHeader header;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(privateKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the PrivateKeyInfo structure
   osMemset(&privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "RSA PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "RSA PRIVATE KEY", buffer, &n,
            &header, NULL);

         //Check status code
         if(!error)
         {
            //Check whether the PEM file is encrypted
            if(pemCompareString(&header.procType.type, "ENCRYPTED"))
            {
               //Perform decryption
               error = pemDecryptMessage(&header, password, buffer, n,
                  buffer, &n);
            }
         }

         //Check status code
         if(!error)
         {
            //Read RSAPrivateKey structure
            error = pkcs8ParseRsaPrivateKey(buffer, n,
               &privateKeyInfo.rsaPrivateKey);
         }

         //Check status code
         if(!error)
         {
            //Set private key algorithm identifier
            privateKeyInfo.oid.value = RSA_ENCRYPTION_OID;
            privateKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

            //Import the RSA private key
            error = pkcs8ImportRsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the RSA private key
            error = pkcs8ImportRsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
#if (PEM_ENCRYPTED_KEY_SUPPORT == ENABLED)
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         uint8_t *data;
         Pkcs8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", buffer,
            &n, NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the EncryptedPrivateKeyInfo structure (refer to RFC 5208,
            //section 6)
            error = pkcs8ParseEncryptedPrivateKeyInfo(buffer, n,
               &encryptedPrivateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Point to the encrypted data
            data = (uint8_t *) encryptedPrivateKeyInfo.encryptedData.value;
            n = encryptedPrivateKeyInfo.encryptedData.length;

            //Decrypt the private key information
            error = pkcs5Decrypt(&encryptedPrivateKeyInfo.encryptionAlgo,
               password, data, n, data, &n);
         }

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(data, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the RSA private key
            error = pkcs8ImportRsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
#else
      //The PEM file contains an encrypted private key
      error = ERROR_DECRYPTION_FAILED;
#endif
   }
   else
   {
      //The PEM file does not contain a valid private key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a DSA public key
 * @param[out] publicKey DSA public key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @return Error code
 **/

error_t pemImportDsaPublicKey(DsaPublicKey *publicKey, const char_t *input,
   size_t length)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(publicKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL,
            NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the DSA public key
            error = x509ImportDsaPublicKey(publicKey, &publicKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a DSA private key
 * @param[out] privateKey DSA private key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t pemImportDsaPrivateKey(DsaPrivateKey *privateKey, const char_t *input,
   size_t length, const char_t *password)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   PemHeader header;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(privateKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the PrivateKeyInfo structure
   osMemset(&privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "DSA PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "DSA PRIVATE KEY", buffer, &n,
            &header, NULL);

         //Check status code
         if(!error)
         {
            //Check whether the PEM file is encrypted
            if(pemCompareString(&header.procType.type, "ENCRYPTED"))
            {
               //Perform decryption
               error = pemDecryptMessage(&header, password, buffer, n,
                  buffer, &n);
            }
         }

         //Check status code
         if(!error)
         {
            //Read DSAPrivateKey structure
            error = pkcs8ParseDsaPrivateKey(buffer, n, &privateKeyInfo.dsaParams,
               &privateKeyInfo.dsaPrivateKey, &privateKeyInfo.dsaPublicKey);
         }

         //Check status code
         if(!error)
         {
            //Set private key algorithm identifier
            privateKeyInfo.oid.value = DSA_OID;
            privateKeyInfo.oid.length = sizeof(DSA_OID);

            //Import the DSA private key
            error = pkcs8ImportDsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the DSA private key
            error = pkcs8ImportDsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
#if (PEM_ENCRYPTED_KEY_SUPPORT == ENABLED)
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         uint8_t *data;
         Pkcs8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", buffer,
            &n, NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the EncryptedPrivateKeyInfo structure (refer to RFC 5208,
            //section 6)
            error = pkcs8ParseEncryptedPrivateKeyInfo(buffer, n,
               &encryptedPrivateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Point to the encrypted data
            data = (uint8_t *) encryptedPrivateKeyInfo.encryptedData.value;
            n = encryptedPrivateKeyInfo.encryptedData.length;

            //Decrypt the private key information
            error = pkcs5Decrypt(&encryptedPrivateKeyInfo.encryptionAlgo,
               password, data, n, data, &n);
         }

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(data, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the DSA private key
            error = pkcs8ImportDsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
#else
      //The PEM file contains an encrypted private key
      error = ERROR_DECRYPTION_FAILED;
#endif
   }
   else
   {
      //The PEM file does not contain a valid private key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing an EC public key
 * @param[out] publicKey EC public key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @return Error code
 **/

error_t pemImportEcPublicKey(EcPublicKey *publicKey, const char_t *input,
   size_t length)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(publicKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL,
            NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EC public key
            error = x509ImportEcPublicKey(publicKey, &publicKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing an EC private key
 * @param[out] privateKey EC private key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t pemImportEcPrivateKey(EcPrivateKey *privateKey, const char_t *input,
   size_t length, const char_t *password)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   PemHeader header;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(privateKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the PrivateKeyInfo structure
   osMemset(&privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "EC PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "EC PRIVATE KEY", buffer, &n,
            &header, NULL);

         //Check status code
         if(!error)
         {
            //Check whether the PEM file is encrypted
            if(pemCompareString(&header.procType.type, "ENCRYPTED"))
            {
               //Perform decryption
               error = pemDecryptMessage(&header, password, buffer, n,
                  buffer, &n);
            }
         }

         //Check status code
         if(!error)
         {
            //Read ECPrivateKey structure
            error = pkcs8ParseEcPrivateKey(buffer, n, &privateKeyInfo.ecParams,
               &privateKeyInfo.ecPrivateKey, &privateKeyInfo.ecPublicKey);
         }

         //Check status code
         if(!error)
         {
            //Set public key algorithm identifier
            privateKeyInfo.oid.value = EC_PUBLIC_KEY_OID;
            privateKeyInfo.oid.length = sizeof(EC_PUBLIC_KEY_OID);

            //Import the EC private key
            error = pkcs8ImportEcPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EC private key
            error = pkcs8ImportEcPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
#if (PEM_ENCRYPTED_KEY_SUPPORT == ENABLED)
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         uint8_t *data;
         Pkcs8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the EncryptedPrivateKeyInfo structure (refer to RFC 5208,
            //section 6)
            error = pkcs8ParseEncryptedPrivateKeyInfo(buffer, n,
               &encryptedPrivateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Point to the encrypted data
            data = (uint8_t *) encryptedPrivateKeyInfo.encryptedData.value;
            n = encryptedPrivateKeyInfo.encryptedData.length;

            //Decrypt the private key information
            error = pkcs5Decrypt(&encryptedPrivateKeyInfo.encryptionAlgo,
               password, data, n, data, &n);
         }

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(data, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EC private key
            error = pkcs8ImportEcPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
#else
      //The PEM file contains an encrypted private key
      error = ERROR_DECRYPTION_FAILED;
#endif
   }
   else
   {
      //The PEM file does not contain a valid private key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a EdDSA public key
 * @param[out] publicKey EdDSA public key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @return Error code
 **/

error_t pemImportEddsaPublicKey(EddsaPublicKey *publicKey, const char_t *input,
   size_t length)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(publicKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n, NULL,
            NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EdDSA public key
            error = x509ImportEddsaPublicKey(publicKey, &publicKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a EdDSA private key
 * @param[out] privateKey EdDSA private key resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t pemImportEddsaPrivateKey(EddsaPrivateKey *privateKey,
   const char_t *input, size_t length, const char_t *password)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   Pkcs8PrivateKeyInfo privateKeyInfo;

   //Check parameters
   if(privateKey == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PRIVATE KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(buffer, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EdDSA private key
            error = pkcs8ImportEddsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else if(pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
#if (PEM_ENCRYPTED_KEY_SUPPORT == ENABLED)
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         uint8_t *data;
         Pkcs8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "ENCRYPTED PRIVATE KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Read the EncryptedPrivateKeyInfo structure (refer to RFC 5208,
            //section 6)
            error = pkcs8ParseEncryptedPrivateKeyInfo(buffer, n,
               &encryptedPrivateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Point to the encrypted data
            data = (uint8_t *) encryptedPrivateKeyInfo.encryptedData.value;
            n = encryptedPrivateKeyInfo.encryptedData.length;

            //Decrypt the private key information
            error = pkcs5Decrypt(&encryptedPrivateKeyInfo.encryptionAlgo,
               password, data, n, data, &n);
         }

         //Check status code
         if(!error)
         {
            //Read the PrivateKeyInfo structure (refer to RFC 5208, section 5)
            error = pkcs8ParsePrivateKeyInfo(data, n, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import the EdDSA private key
            error = pkcs8ImportEddsaPrivateKey(privateKey, &privateKeyInfo);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
#else
      //The PEM file contains an encrypted private key
      error = ERROR_DECRYPTION_FAILED;
#endif
   }
   else
   {
      //The PEM file does not contain a valid private key
      error = ERROR_END_OF_FILE;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract the public key type from a PEM file
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @return Public key type
 **/

X509KeyType pemGetPublicKeyType(const char_t *input, size_t length)
{
   error_t error;
   size_t n;
   uint8_t *buffer;
   X509KeyType keyType;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Initialize variable
   keyType = X509_KEY_TYPE_UNKNOWN;

#if (RSA_SUPPORT == ENABLED)
   //PEM container with "RSA PUBLIC KEY" label?
   if(pemDecodeFile(input, length, "RSA PUBLIC KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //The PEM file contains an RSA public key (PKCS #1 format)
      keyType = X509_KEY_TYPE_RSA;
   }
   else
#endif
   //PEM container with "PUBLIC KEY" label?
   if(pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Check public key algorithm identifier
            keyType = x509GetPublicKeyType(publicKeyInfo.oid.value,
               publicKeyInfo.oid.length);

#if (EC_SUPPORT == ENABLED)
            //EC public key identifier?
            if(keyType == X509_KEY_TYPE_EC)
            {
               //SM2 elliptic curve?
               if(OID_COMP(publicKeyInfo.ecParams.namedCurve.value,
                  publicKeyInfo.ecParams.namedCurve.length, SM2_OID) == 0)
               {
                  //The PEM file contains an SM2 public key
                  keyType = X509_KEY_TYPE_SM2;
               }
            }
#endif
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
   }

   //Return the public key type
   return keyType;
}


/**
 * @brief Extract elliptic curve parameters from a PEM file
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @return Elliptic curve parameters
 **/

const EcCurve *pemGetPublicKeyCurve(const char_t *input, size_t length)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   const EcCurve *curve;

   //Initialize variable
   curve = NULL;

   //The type of data encoded is labeled depending on the type label in
   //the "-----BEGIN " line (refer to RFC 7468, section 2)
   if(pemDecodeFile(input, length, "EC PARAMETERS", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      X509EcParameters ecParams;

      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "EC PARAMETERS", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //Parse ECParameters structure
            error = x509ParseEcParameters(buffer, n, &ecParams);
         }

         //Check status code
         if(!error)
         {
            //Get the elliptic curve that matches the OID
            curve = ecGetCurve(ecParams.namedCurve.value,
               ecParams.namedCurve.length);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
   }
   else if(pemDecodeFile(input, length, "PUBLIC KEY", NULL, &n, NULL,
      NULL) == NO_ERROR)
   {
      X509SubjectPublicKeyInfo publicKeyInfo;

      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "PUBLIC KEY", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
            //structure (refer to RFC 7468, section 13)
            error = x509ParseSubjectPublicKeyInfo(buffer, n, &n, &publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Get the elliptic curve that matches the OID
            curve = ecGetCurve(publicKeyInfo.ecParams.namedCurve.value,
               publicKeyInfo.ecParams.namedCurve.length);
         }

         //Release previously allocated memory
         cryptoFreeMem(buffer);
      }
   }

   //Return the elliptic curve parameters, if any
   return curve;
#else
   //Not implemented
   return NULL;
#endif
}

#endif
