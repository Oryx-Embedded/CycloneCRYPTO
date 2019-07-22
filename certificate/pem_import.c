/**
 * @file pem_import.c
 * @brief PEM file import functions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2019 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.9.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "certificate/pem_import.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "encoding/base64.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Decode a PEM file containing Diffie-Hellman parameters
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] params Diffie-Hellman parameters resulting from the parsing process
 * @return Error code
 **/

error_t pemImportDhParameters(const char_t *input, size_t length, DhParameters *params)
{
#if (DH_SUPPORT == ENABLED)
   error_t error;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Search for the beginning tag
   k = pemSearchTag(input, length, "-----BEGIN DH PARAMETERS-----", 29);
   //Failed to find the specified tag?
   if(k < 0)
      return ERROR_INVALID_SYNTAX;

   //Advance the pointer over the tag
   input += k + 29;
   length -= k + 29;

   //Search for the end tag
   k = pemSearchTag(input, length, "-----END DH PARAMETERS-----", 27);
   //Invalid PEM file?
   if(k <= 0)
      return ERROR_INVALID_SYNTAX;

   //Length of the PEM structure
   length = k;

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //The Diffie-Hellman parameters are encapsulated within a sequence
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the prime modulus
      error = asn1ReadMpi(data, length, &tag, &params->p);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the generator
      error = asn1ReadMpi(data, length, &tag, &params->g);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("Diffie-Hellman parameters:\r\n");
      TRACE_DEBUG("  Prime modulus:\r\n");
      TRACE_DEBUG_MPI("    ", &params->p);
      TRACE_DEBUG("  Generator:\r\n");
      TRACE_DEBUG_MPI("    ", &params->g);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      mpiFree(&params->p);
      mpiFree(&params->g);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a RSA public key
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key RSA public key resulting from the parsing process
 * @return Error code
 **/


error_t pemImportRsaPublicKey(const char_t *input, size_t length, RsaPublicKey *key)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   bool_t pkcs8Format;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //PKCS #8 format?
   if(pemSearchTag(input, length, "-----BEGIN PUBLIC KEY-----", 26) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN PUBLIC KEY-----", 26);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 26;
      length -= k + 26;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END PUBLIC KEY-----", 24);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #8
      pkcs8Format = TRUE;
   }
   else
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN RSA PUBLIC KEY-----", 30);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 30;
      length -= k + 30;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END RSA PUBLIC KEY-----", 28);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #1
      pkcs8Format = FALSE;
   }

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //PKCS #8 format?
      if(pkcs8Format)
      {
         //PKCS #8 describes a generic syntax for encoding public keys
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the publicKeyAlgorithm field
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Save the position of the publicKey field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the algorithm identifier (OID)
         error = asn1ReadTag(tag.value, tag.length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Check algorithm identifier
         if(asn1CheckOid(&tag, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) &&
            asn1CheckOid(&tag, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
         {
            //Report an error
            error = ERROR_WRONG_IDENTIFIER;
            break;
         }

         //The publicKey field is encapsulated within an bit string
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
         //Invalid tag?
         if(error)
            break;

         //The bit string shall contain an initial octet which encodes the number
         //of unused bits in the final subsequent octet
         if(tag.length < 1 || tag.value[0] != 0x00)
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Point to the content of the publicKey structure
         data = tag.value + 1;
         length = tag.length - 1;

         //Display ASN.1 structure
         error = asn1DumpObject(data, length, 0);
         //Any error to report?
         if(error)
            break;
      }

      //Read the contents of the publicKey structure
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the modulus
      error = asn1ReadMpi(data, length, &tag, &key->n);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the public exponent
      error = asn1ReadMpi(data, length, &tag, &key->e);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("RSA public key:\r\n");
      TRACE_DEBUG("  Modulus:\r\n");
      TRACE_DEBUG_MPI("    ", &key->n);
      TRACE_DEBUG("  Public exponent:\r\n");
      TRACE_DEBUG_MPI("    ", &key->e);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePublicKey(key);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a RSA private key
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key RSA private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportRsaPrivateKey(const char_t *input, size_t length, RsaPrivateKey *key)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   bool_t pkcs8Format;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //PKCS #8 format?
   if(pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 27;
      length -= k + 27;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END PRIVATE KEY-----", 25);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #8
      pkcs8Format = TRUE;
   }
   else
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN RSA PRIVATE KEY-----", 31);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 31;
      length -= k + 31;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END RSA PRIVATE KEY-----", 29);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #1
      pkcs8Format = FALSE;
   }

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //PKCS #8 format?
      if(pkcs8Format)
      {
         //PKCS #8 describes a generic syntax for encoding private keys
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the version field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
         //Invalid tag?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Save the position of the privateKey field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the algorithm identifier (OID)
         error = asn1ReadTag(tag.value, tag.length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Check algorithm identifier
         if(asn1CheckOid(&tag, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)) &&
            asn1CheckOid(&tag, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
         {
            //Report an error
            error = ERROR_WRONG_IDENTIFIER;
            break;
         }

         //The privateKey field is encapsulated within an octet string
         error = asn1ReadOctetString(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the content of the privateKey structure
         data = tag.value;
         length = tag.length;

         //Display ASN.1 structure
         error = asn1DumpObject(data, length, 0);
         //Any error to report?
         if(error)
            break;
      }

      //Read the contents of the privateKey structure
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the version field
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         break;

      //Skip the version field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the modulus
      error = asn1ReadMpi(data, length, &tag, &key->n);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the public exponent
      error = asn1ReadMpi(data, length, &tag, &key->e);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the private exponent
      error = asn1ReadMpi(data, length, &tag, &key->d);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the first factor
      error = asn1ReadMpi(data, length, &tag, &key->p);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the second factor
      error = asn1ReadMpi(data, length, &tag, &key->q);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the first exponent
      error = asn1ReadMpi(data, length, &tag, &key->dp);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the second exponent
      error = asn1ReadMpi(data, length, &tag, &key->dq);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the coefficient
      error = asn1ReadMpi(data, length, &tag, &key->qinv);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("RSA private key:\r\n");
      TRACE_DEBUG("  Modulus:\r\n");
      TRACE_DEBUG_MPI("    ", &key->n);
      TRACE_DEBUG("  Public exponent:\r\n");
      TRACE_DEBUG_MPI("    ", &key->e);
      TRACE_DEBUG("  Private exponent:\r\n");
      TRACE_DEBUG_MPI("    ", &key->d);
      TRACE_DEBUG("  Prime 1:\r\n");
      TRACE_DEBUG_MPI("    ", &key->p);
      TRACE_DEBUG("  Prime 2:\r\n");
      TRACE_DEBUG_MPI("    ", &key->q);
      TRACE_DEBUG("  Prime exponent 1:\r\n");
      TRACE_DEBUG_MPI("    ", &key->dp);
      TRACE_DEBUG("  Prime exponent 2:\r\n");
      TRACE_DEBUG_MPI("    ", &key->dq);
      TRACE_DEBUG("  Coefficient:\r\n");
      TRACE_DEBUG_MPI("    ", &key->qinv);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePrivateKey(key);
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
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key DSA public key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportDsaPublicKey(const char_t *input, size_t length, DsaPublicKey *key)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   bool_t pkcs8Format;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   const uint8_t *publicKey;
   size_t publicKeyLen;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //PKCS #8 format?
   if(pemSearchTag(input, length, "-----BEGIN PUBLIC KEY-----", 26) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN PUBLIC KEY-----", 26);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 26;
      length -= k + 26;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END PUBLIC KEY-----", 24);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #8
      pkcs8Format = TRUE;
   }
   else
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN DSA PUBLIC KEY-----", 30);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 30;
      length -= k + 30;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END DSA PUBLIC KEY-----", 28);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #1
      pkcs8Format = FALSE;
   }

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //PKCS #8 format?
      if(pkcs8Format)
      {
         //PKCS #8 describes a generic syntax for encoding public keys
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the publicKeyAlgorithm field
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Save the position of the publicKey field
         publicKey = data + tag.totalLength;
         publicKeyLen = length - tag.totalLength;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the algorithm identifier (OID)
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Check algorithm identifier
         error = asn1CheckOid(&tag, DSA_OID, sizeof(DSA_OID));
         //Wrong identifier?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;

         //The DSA parameters are encapsulated within a sequence
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read p
         error = asn1ReadMpi(data, length, &tag, &key->p);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read q
         error = asn1ReadMpi(data, length, &tag, &key->q);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read g
         error = asn1ReadMpi(data, length, &tag, &key->g);
         //Any error to report?
         if(error)
            break;

         //The publicKey field is encapsulated within an bit string
         error = asn1ReadTag(publicKey, publicKeyLen, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
         //Invalid tag?
         if(error)
            break;

         //The bit string shall contain an initial octet which encodes the number
         //of unused bits in the final subsequent octet
         if(tag.length < 1 || tag.value[0] != 0x00)
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Point to the content of the publicKey structure
         data = tag.value + 1;
         length = tag.length - 1;

         //Display ASN.1 structure
         error = asn1DumpObject(data, length, 0);
         //Any error to report?
         if(error)
            break;

         //Read the public value
         error = asn1ReadMpi(data, length, &tag, &key->y);
         //Any error to report?
         if(error)
            break;
      }
      else
      {
         //The DSA key and parameters are encapsulated within a sequence
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the public value
         error = asn1ReadMpi(data, length, &tag, &key->y);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read p
         error = asn1ReadMpi(data, length, &tag, &key->p);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read q
         error = asn1ReadMpi(data, length, &tag, &key->q);
         //Any error to report?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read g
         error = asn1ReadMpi(data, length, &tag, &key->g);
         //Any error to report?
         if(error)
            break;
      }

      //Debug message
      TRACE_DEBUG("DSA public key:\r\n");
      TRACE_DEBUG("  p:\r\n");
      TRACE_DEBUG_MPI("    ", &key->p);
      TRACE_DEBUG("  q:\r\n");
      TRACE_DEBUG_MPI("    ", &key->q);
      TRACE_DEBUG("  g:\r\n");
      TRACE_DEBUG_MPI("    ", &key->g);
      TRACE_DEBUG("  y:\r\n");
      TRACE_DEBUG_MPI("    ", &key->y);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePublicKey(key);
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
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key DSA private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportDsaPrivateKey(const char_t *input, size_t length, DsaPrivateKey *key)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   bool_t pkcs8Format;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   const uint8_t *privateKey;
   size_t privateKeyLen;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize private key
   privateKey = NULL;
   privateKeyLen = 0;

   //PKCS #8 format?
   if(pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 27;
      length -= k + 27;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END PRIVATE KEY-----", 25);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #8
      pkcs8Format = TRUE;
   }
   else
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN DSA PRIVATE KEY-----", 31);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 31;
      length -= k + 31;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END DSA PRIVATE KEY-----", 29);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by RFC 4211, section 4.2.2.2
      pkcs8Format = FALSE;
   }

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //PKCS #8 format?
      if(pkcs8Format)
      {
         //PKCS #8 describes a generic syntax for encoding private keys
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the version field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
         //Invalid tag?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Save the position of the privateKey field
         privateKey = data + tag.totalLength;
         privateKeyLen = length - tag.totalLength;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the algorithm identifier (OID)
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Check algorithm identifier
         error = asn1CheckOid(&tag, DSA_OID, sizeof(DSA_OID));
         //Wrong identifier?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length -= tag.totalLength;

         //The DSA parameters are encapsulated within a sequence
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;
      }
      else
      {
         //The DSA parameters and keys are encapsulated within a sequence
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the version
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
         //Invalid tag?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;
      }

      //Read p
      error = asn1ReadMpi(data, length, &tag, &key->p);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read q
      error = asn1ReadMpi(data, length, &tag, &key->q);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read g
      error = asn1ReadMpi(data, length, &tag, &key->g);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //PKCS #8 format?
      if(pkcs8Format)
      {
         //The privateKey field is encapsulated within an octet string
         error = asn1ReadOctetString(privateKey, privateKeyLen, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the content of the privateKey structure
         data = tag.value;
         length = tag.length;

         //Display ASN.1 structure
         error = asn1DumpObject(data, length, 0);
         //Any error to report?
         if(error)
            break;
      }
      else
      {
         //Read the public value
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
         //Invalid tag?
         if(error)
            break;

         //Skip the public value
         data += tag.totalLength;
         length -= tag.totalLength;
      }

      //Read the private value
      error = asn1ReadMpi(data, length, &tag, &key->x);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("DSA private key:\r\n");
      TRACE_DEBUG("  p:\r\n");
      TRACE_DEBUG_MPI("    ", &key->p);
      TRACE_DEBUG("  q:\r\n");
      TRACE_DEBUG_MPI("    ", &key->q);
      TRACE_DEBUG("  g:\r\n");
      TRACE_DEBUG_MPI("    ", &key->g);
      TRACE_DEBUG("  x:\r\n");
      TRACE_DEBUG_MPI("    ", &key->x);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePrivateKey(key);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing EC domain parameters
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] params EC domain parameters
 * @return Error code
 **/

error_t pemImportEcParameters(const char_t *input, size_t length, EcDomainParameters *params)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   bool_t ecParamsFormat;
   bool_t pkcs8Format;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   Asn1Tag tag;
   const EcCurveInfo *curveInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   ecParamsFormat = FALSE;
   pkcs8Format = FALSE;

   //Check format
   if(pemSearchTag(input, length, "-----BEGIN EC PARAMETERS-----", 29) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN EC PARAMETERS-----", 29);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 29;
      length -= k + 29;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END EC PARAMETERS-----", 27);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure is described by RFC 3279, section 2.3.5
      ecParamsFormat = TRUE;
   }
   else if(pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 27;
      length -= k + 27;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END PRIVATE KEY-----", 25);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure is described by RFC 5208 (PKCS #8)
      pkcs8Format = TRUE;
   }
   else if(pemSearchTag(input, length, "-----BEGIN EC PRIVATE KEY-----", 30) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN EC PRIVATE KEY-----", 30);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 30;
      length -= k + 30;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END EC PRIVATE KEY-----", 28);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #1
   }

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //Check format
      if(ecParamsFormat)
      {
         //Just for sanity
      }
      else if(pkcs8Format)
      {
         //PKCS #8 describes a generic syntax for encoding private keys
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the version field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
         //Invalid tag?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the algorithm identifier (OID)
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Check algorithm identifier
         error = asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID));
         //Wrong identifier?
         if(error)
            break;

         //Point to the next field
         data += tag.totalLength;
         length += tag.totalLength;
      }
      else
      {
         //The EC parameters are encapsulated within a sequence
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the version field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
         //Invalid tag?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKey field
         error = asn1ReadOctetString(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Skip the privateKey field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Explicit tagging shall be used to encode the curve identifier
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            return error;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_CONTEXT_SPECIFIC, 0);
         //Failed to decode ASN.1 tag?
         if(error)
            return error;

         //Read the inner tag
         data = tag.value;
         length = tag.length;
      }

      //Read the curve identifier
      error = asn1ReadOid(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Retrieve EC domain parameters
      curveInfo = ecGetCurveInfo(tag.value, tag.length);
      //Make sure the specified elliptic curve is supported
      if(curveInfo == NULL)
      {
         //Report an error
         error = ERROR_ILLEGAL_PARAMETER;
         //Exit immediately
         break;
      }

      //Load EC domain parameters
      error = ecLoadDomainParameters(params, curveInfo);
      //Any error to report?
      if(error)
         break;

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreeDomainParameters(params);
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
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key EC public key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEcPublicKey(const char_t *input, size_t length, EcPoint *key)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   const uint8_t *publicKey;
   size_t publicKeyLen;
   const EcCurveInfo *curveInfo;
   EcDomainParameters params;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Search for the beginning tag
   k = pemSearchTag(input, length, "-----BEGIN PUBLIC KEY-----", 26);
   //Failed to find the specified tag?
   if(k < 0)
      return ERROR_INVALID_SYNTAX;

   //Advance the pointer over the tag
   input += k + 26;
   length -= k + 26;

   //Search for the end tag
   k = pemSearchTag(input, length, "-----END PUBLIC KEY-----", 24);
   //Invalid PEM file?
   if(k <= 0)
      return ERROR_INVALID_SYNTAX;

   //Length of the PEM structure
   length = k;

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Initialize EC domain parameters
   ecInitDomainParameters(&params);

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //PKCS #8 describes a generic syntax for encoding public keys
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the publicKeyAlgorithm field
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Save the position of the publicKey field
      publicKey = data + tag.totalLength;
      publicKeyLen = length - tag.totalLength;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the algorithm identifier (OID)
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Check algorithm identifier
      error = asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID));
      //Wrong identifier?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the curve identifier
      error = asn1ReadOid(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Retrieve EC domain parameters
      curveInfo = ecGetCurveInfo(tag.value, tag.length);
      //Make sure the specified elliptic curve is supported
      if(curveInfo == NULL)
      {
         //Report an error
         error = ERROR_ILLEGAL_PARAMETER;
         //Exit immediately
         break;
      }

      //Load EC domain parameters
      error = ecLoadDomainParameters(&params, curveInfo);
      //Any error to report?
      if(error)
         break;

      //The publicKey field is encapsulated within an bit string
      error = asn1ReadTag(publicKey, publicKeyLen, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
      //Invalid tag?
      if(error)
         break;

      //The bit string shall contain an initial octet which encodes the number
      //of unused bits in the final subsequent octet
      if(tag.length < 1 || tag.value[0] != 0x00)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the content of the publicKey structure
      data = tag.value + 1;
      length = tag.length - 1;

      //Read the EC public key
      error = ecImport(&params, key, data, length);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Public key X:\r\n");
      TRACE_DEBUG_MPI("    ", &key->x);
      TRACE_DEBUG("  Public key Y:\r\n");
      TRACE_DEBUG_MPI("    ", &key->y);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   ecFreeDomainParameters(&params);
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFree(key);
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
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key EC private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEcPrivateKey(const char_t *input, size_t length, Mpi *key)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   bool_t pkcs8Format;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //PKCS #8 format?
   if(pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27) >= 0)
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 27;
      length -= k + 27;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END PRIVATE KEY-----", 25);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by PKCS #8
      pkcs8Format = TRUE;
   }
   else
   {
      //Search for the beginning tag
      k = pemSearchTag(input, length, "-----BEGIN EC PRIVATE KEY-----", 30);
      //Failed to find the specified tag?
      if(k < 0)
         return ERROR_INVALID_SYNTAX;

      //Advance the pointer over the tag
      input += k + 30;
      length -= k + 30;

      //Search for the end tag
      k = pemSearchTag(input, length, "-----END EC PRIVATE KEY-----", 28);
      //Invalid PEM file?
      if(k <= 0)
         return ERROR_INVALID_SYNTAX;

      //Length of the PEM structure
      length = k;

      //The structure of the private key is described by RFC 5915
      pkcs8Format = FALSE;
   }

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //PKCS #8 format?
      if(pkcs8Format)
      {
         //PKCS #8 describes a generic syntax for encoding private keys
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;

         //Read the version field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
         //Invalid tag?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadSequence(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Save the position of the privateKey field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the algorithm identifier (OID)
         error = asn1ReadTag(tag.value, tag.length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Check algorithm identifier
         error = asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID));
         //Wrong identifier?
         if(error)
            break;

         //The privateKey field is encapsulated within an octet string
         error = asn1ReadOctetString(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Point to the content of the privateKey structure
         data = tag.value;
         length = tag.length;

         //Display ASN.1 structure
         error = asn1DumpObject(data, length, 0);
         //Any error to report?
         if(error)
            break;
      }

      //Read the contents of the privateKey structure
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the version field
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         break;

      //Skip the version field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the privateKey field
      error = asn1ReadOctetString(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Read the EC private key
      error = mpiReadRaw(key, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("EC private key:\r\n");
      TRACE_DEBUG_MPI("  ", key);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      mpiFree(key);
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
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key EdDSA public key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEddsaPublicKey(const char_t *input, size_t length, EddsaPublicKey *key)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Search for the beginning tag
   k = pemSearchTag(input, length, "-----BEGIN PUBLIC KEY-----", 26);
   //Failed to find the specified tag?
   if(k < 0)
      return ERROR_INVALID_SYNTAX;

   //Advance the pointer over the tag
   input += k + 26;
   length -= k + 26;

   //Search for the end tag
   k = pemSearchTag(input, length, "-----END PUBLIC KEY-----", 24);
   //Invalid PEM file?
   if(k <= 0)
      return ERROR_INVALID_SYNTAX;

   //Length of the PEM structure
   length = k;

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //PKCS #8 describes a generic syntax for encoding public keys
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the publicKeyAlgorithm field
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Save the position of the publicKey field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the algorithm identifier (OID)
      error = asn1ReadTag(tag.value, tag.length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Check algorithm identifier
      if(asn1CheckOid(&tag, ED25519_OID, sizeof(ED25519_OID)) &&
         asn1CheckOid(&tag, ED448_OID, sizeof(ED448_OID)))
      {
         //Report an error
         error = ERROR_WRONG_IDENTIFIER;
         break;
      }

      //The publicKey field is encapsulated within an bit string
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING);
      //Invalid tag?
      if(error)
         break;

      //The bit string shall contain an initial octet which encodes the number
      //of unused bits in the final subsequent octet
      if(tag.length < 1 || tag.value[0] != 0x00)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the content of the publicKey structure
      data = tag.value + 1;
      length = tag.length - 1;

      //Read the EdDSA public key
      error = mpiImport(&key->q, data, length, MPI_FORMAT_LITTLE_ENDIAN);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("EdDSA public key:\r\n");
      TRACE_DEBUG_MPI("  ", &key->q);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePublicKey(key);
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
 * @param[in] input Pointer to the PEM structure
 * @param[in] length Length of the PEM structure
 * @param[out] key EdDSA private key resulting from the parsing process
 * @return Error code
 **/

error_t pemImportEddsaPrivateKey(const char_t *input, size_t length, EddsaPrivateKey *key)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t i;
   size_t j;
   int_t k;
   char_t *buffer;
   const uint8_t *data;
   Asn1Tag tag;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL)
      return ERROR_INVALID_PARAMETER;

   //Search for the beginning tag
   k = pemSearchTag(input, length, "-----BEGIN PRIVATE KEY-----", 27);
   //Failed to find the specified tag?
   if(k < 0)
      return ERROR_INVALID_SYNTAX;

   //Advance the pointer over the tag
   input += k + 27;
   length -= k + 27;

   //Search for the end tag
   k = pemSearchTag(input, length, "-----END PRIVATE KEY-----", 25);
   //Invalid PEM file?
   if(k <= 0)
      return ERROR_INVALID_SYNTAX;

   //Length of the PEM structure
   length = k;

   //Allocate a memory buffer to hold the decoded data
   buffer = cryptoAllocMem(length);
   //Failed to allocate memory?
   if(buffer == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the contents of the PEM structure
   cryptoMemcpy(buffer, input, length);

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if(buffer[i] != '\r' && buffer[i] != '\n')
         buffer[j++] = buffer[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode(buffer, j, buffer, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Point to the resulting ASN.1 structure
      data = (uint8_t *) buffer;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //The EdDSA private key is encapsulated within a sequence
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the version field
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         break;

      //Skip the version field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the privateKeyAlgorithm field
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Save the position of the privateKey field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the algorithm identifier (OID)
      error = asn1ReadTag(tag.value, tag.length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Check algorithm identifier
      if(asn1CheckOid(&tag, ED25519_OID, sizeof(ED25519_OID)) &&
         asn1CheckOid(&tag, ED448_OID, sizeof(ED448_OID)))
      {
         error = ERROR_WRONG_IDENTIFIER;
         break;
      }

      //The privateKey field is encapsulated within an octet string
      error = asn1ReadOctetString(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Point to the content of the privateKey structure
      data = tag.value;
      length = tag.length;

      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //Read the privateKey field
      error = asn1ReadOctetString(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Read the EdDSA private key
      error = mpiImport(&key->d, tag.value, tag.length, MPI_FORMAT_LITTLE_ENDIAN);
      //Any error to report?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("EdDSA private key:\r\n");
      TRACE_DEBUG_MPI("  ", &key->d);

      //End of exception handling block
   } while(0);

   //Release previously allocated memory
   cryptoFreeMem(buffer);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePrivateKey(key);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode a PEM file containing a certificate
 * @param[in,out] input Pointer to the PEM structure
 * @param[in,out] inputLen Length of the PEM structure
 * @param[in,out] output Pointer to the DER encoded certificate
 * @param[in,out] outputSize Size of the memory block that holds the DER certificate
 * @param[out] outputLen Length of the DER encoded certificate
 * @return Error code
 **/

error_t pemImportCertificate(const char_t **input, size_t *inputLen,
   uint8_t **output, size_t *outputSize, size_t *outputLen)
{
   error_t error;
   size_t length;
   size_t i;
   size_t j;
   int_t k;

   //Check parameters
   if(input == NULL || inputLen == NULL)
      return ERROR_INVALID_PARAMETER;
   if(output == NULL || outputSize == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Search for the beginning tag
   k = pemSearchTag(*input, *inputLen, "-----BEGIN CERTIFICATE-----", 27);
   //Failed to find the specified tag?
   if(k < 0)
      return ERROR_END_OF_FILE;

   //Advance the input pointer over the tag
   *input += k + 27;
   *inputLen -= k + 27;

   //Search for the end tag
   k = pemSearchTag(*input, *inputLen, "-----END CERTIFICATE-----", 25);
   //Invalid PEM file?
   if(k <= 0)
      return ERROR_INVALID_SYNTAX;

   //Length of the PEM structure
   length = k;

   //Increase buffer size?
   if(length > *outputSize)
   {
      //Release previously allocated buffer if necessary
      if(*output != NULL)
      {
         cryptoFreeMem(*output);
         *output = NULL;
         *outputSize = 0;
      }

      //Allocate a memory buffer to hold the decoded data
      *output = cryptoAllocMem(length);
      //Failed to allocate memory?
      if(*output == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Record the size of the buffer
      *outputSize = length;
   }

   //Copy the contents of the PEM structure
   cryptoMemcpy(*output, *input, length);

   //Advance the input pointer over the certificate
   *input += length + 25;
   *inputLen -= length + 25;

   //Remove carriage returns and line feeds
   for(i = 0, j = 0; i < length; i++)
   {
      if((*output)[i] != '\r' && (*output)[i] != '\n')
         (*output)[j++] = (*output)[i];
   }

   //Start of exception handling block
   do
   {
      //The contents of the PEM file is Base64-encoded
      error = base64Decode((char_t *) *output, j, *output, &length);
      //Failed to decode the file?
      if(error)
         break;

      //Display ASN.1 structure
      error = asn1DumpObject(*output, length, 0);
      //Any error to report?
      if(error)
         break;

      //End of exception handling block
   } while(0);

   //Clean up side effects
   if(error)
   {
      //Release previously allocated memory
      cryptoFreeMem(*output);
      *output = NULL;
      *outputSize = 0;
   }

   //Size of the decoded certificate
   *outputLen = length;
   //Return status code
   return error;
}


/**
 * @brief Search a string for a given tag
 * @param[in] s String to search
 * @param[in] sLen Length of the string to search
 * @param[in] tag String containing the tag to search for
 * @param[in] tagLen Length of the tag
 * @return The index of the first occurrence of the tag in the string,
 *   or -1 if the tag does not appear in the string
 **/

int_t pemSearchTag(const char_t *s, size_t sLen, const char_t *tag, size_t tagLen)
{
   size_t i;
   size_t j;

   //Loop through input string
   for(i = 0; (i + tagLen) <= sLen; i++)
   {
      //Compare current substring with the given tag
      for(j = 0; j < tagLen; j++)
      {
         if(s[i + j] != tag[j])
            break;
      }

      //Check whether the tag has been found
      if(j == tagLen)
         return i;
   }

   //The tag does not appear in the string
   return -1;
}

#endif
