/**
 * @file pem_import.c
 * @brief PEM file import functions
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
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
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "certificate/pem_import.h"
#include "encoding/asn1.h"
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
      //The PEM file is Base64 encoded...
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
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
      //The tag does not match the criteria?
      if(error)
         break;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read the prime modulus
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the prime modulus to a multiple precision integer
      error = mpiReadRaw(&params->p, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the generator
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the generator to a multiple precision integer
      error = mpiReadRaw(&params->g, tag.value, tag.length);
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
      //The PEM file is Base64 encoded...
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
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         //The tag does not match the criteria?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         error = asn1CheckOid(&tag, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID));
         //Wrong identifier?
         if(error)
            break;

         //The privateKey field is encapsulated within an octet string
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING);
         //The tag does not match the criteria?
         if(error)
            break;

         //Display ASN.1 structure
         error = asn1DumpObject(tag.value, tag.length, 0);
         //Any error to report?
         if(error)
            break;

         //Point to the content of the privateKey structure
         data = tag.value;
         length = tag.length;
      }

      //Read the contents of the privateKey structure
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
      //The tag does not match the criteria?
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
      //The tag does not match the criteria?
      if(error)
         break;

      //Skip the version field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the modulus
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the modulus to a multiple precision integer
      error = mpiReadRaw(&key->n, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the public exponent
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the public exponent to a multiple precision integer
      error = mpiReadRaw(&key->e, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the private exponent
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the private exponent to a multiple precision integer
      error = mpiReadRaw(&key->d, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the first factor
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the first factor to a multiple precision integer
      error = mpiReadRaw(&key->p, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the second factor
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the second factor to a multiple precision integer
      error = mpiReadRaw(&key->q, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the first exponent
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the first exponent to a multiple precision integer
      error = mpiReadRaw(&key->dp, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the second exponent
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the second exponent to a multiple precision integer
      error = mpiReadRaw(&key->dq, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the coefficient
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the coefficient to a multiple precision integer
      error = mpiReadRaw(&key->qinv, tag.value, tag.length);
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

   //Clean up side effects if necessary
   if(error)
      rsaFreePrivateKey(key);

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
      //The PEM file is Base64 encoded...
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
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         //The tag does not match the criteria?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
         if(error)
            break;

         //Point to the first field of the sequence
         data = tag.value;
         length = tag.length;
      }
      else
      {
         //The DSA parameters and keys are encapsulated within a sequence
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         //The tag does not match the criteria?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;
      }

      //Read p
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert p to a multiple precision integer
      error = mpiReadRaw(&key->p, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read q
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert q to a multiple precision integer
      error = mpiReadRaw(&key->q, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read g
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert g to a multiple precision integer
      error = mpiReadRaw(&key->g, tag.value, tag.length);
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
         error = asn1ReadTag(privateKey, privateKeyLen, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING);
         //The tag does not match the criteria?
         if(error)
            break;

         //Display ASN.1 structure
         error = asn1DumpObject(tag.value, tag.length, 0);
         //Any error to report?
         if(error)
            break;

         //Point to the content of the privateKey structure
         data = tag.value;
         length = tag.length;
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
         //The tag does not match the criteria?
         if(error)
            break;

         //Skip the public value
         data += tag.totalLength;
         length -= tag.totalLength;
      }

      //Read the private value
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //The tag does not match the criteria?
      if(error)
         break;

      //Convert the private value to a multiple precision integer
      error = mpiReadRaw(&key->x, tag.value, tag.length);
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

   //Clean up side effects if necessary
   if(error)
      dsaFreePrivateKey(key);

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
      //The PEM file is Base64 encoded...
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
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         //The tag does not match the criteria?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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

      //Read the curve identifier
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_OBJECT_IDENTIFIER);
      //The tag does not match the criteria?
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

   //Clean up side effects if necessary
   if(error)
      ecFreeDomainParameters(params);

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
      //The PEM file is Base64 encoded...
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
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         //The tag does not match the criteria?
         if(error)
            break;

         //Skip the version field
         data += tag.totalLength;
         length -= tag.totalLength;

         //Read the privateKeyAlgorithm field
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
         //The tag does not match the criteria?
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
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Enforce encoding, class and type
         error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING);
         //The tag does not match the criteria?
         if(error)
            break;

         //Display ASN.1 structure
         error = asn1DumpObject(tag.value, tag.length, 0);
         //Any error to report?
         if(error)
            break;

         //Point to the content of the privateKey structure
         data = tag.value;
         length = tag.length;
      }

      //Read the contents of the privateKey structure
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, TRUE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE);
      //The tag does not match the criteria?
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
      //The tag does not match the criteria?
      if(error)
         break;

      //Skip the version field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the privateKey field
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING);
      //The tag does not match the criteria?
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

   //Clean up side effects if necessary
   if(error)
      mpiFree(key);

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
      //The PEM file is Base64 encoded...
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
