/**
 * @file pem_import.c
 * @brief PEM file import functions
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
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Decode a PEM file containing a certificate
 * @param[in] input Pointer to the PEM string
 * @param[in] inputLen Length of the PEM string
 * @param[out] output Pointer to the DER-encoded certificate
 * @param[out] outputLen Length of the DER-encoded certificate, in bytes
 * @param[out] consumed Total number of characters that have been consumed
 *   (optional parameter)
 * @return Error code
 **/

error_t pemImportCertificate(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen, size_t *consumed)
{
   error_t error;

   //Check parameters
   if(input == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //X.509 certificates are encoded using the "CERTIFICATE" label
   error = pemDecodeFile(input, inputLen, "CERTIFICATE", output, outputLen,
      NULL, consumed);

   //Return status code
   return error;
}


/**
 * @brief Decode a PEM file containing a certificate revocation list
 * @param[in] input Pointer to the PEM string
 * @param[in] inputLen Length of the PEM string
 * @param[out] output Pointer to the DER-encoded CRL
 * @param[out] outputLen Length of the DER-encoded CRL, in bytes
 * @param[out] consumed Total number of characters that have been consumed
 *   (optional parameter)
 * @return Error code
 **/

error_t pemImportCrl(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen, size_t *consumed)
{
   error_t error;

   //Check parameters
   if(input == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //CRLs are encoded using the "X509 CRL" label
   error = pemDecodeFile(input, inputLen, "X509 CRL", output, outputLen,
      NULL, consumed);

   //Return status code
   return error;
}


/**
 * @brief Decode a PEM file containing a certification signing request
 * @param[in] input Pointer to the PEM string
 * @param[in] inputLen Length of the PEM string
 * @param[out] output Pointer to the DER-encoded CSR
 * @param[out] outputLen Length of the DER-encoded CSR, in bytes
 * @return Error code
 **/

error_t pemImportCsr(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;

   //Check parameters
   if(input == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //CSRs are encoded using the "CERTIFICATE REQUEST" label
   error = pemDecodeFile(input, inputLen, "CERTIFICATE REQUEST", output,
      outputLen, NULL, NULL);

   //Return status code
   return error;
}


/**
 * @brief Decode a PEM file containing Diffie-Hellman parameters
 * @param[out] params Diffie-Hellman parameters resulting from the parsing process
 * @param[in] input Pointer to the PEM string
 * @param[in] length Length of the PEM string
 * @return Error code
 **/

error_t pemImportDhParameters(DhParameters *params, const char_t *input,
   size_t length)
{
#if (DH_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   const uint8_t *p;
   Asn1Tag tag;

   //Check parameters
   if(params == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   p = NULL;
   n = 0;

   //Diffie-Hellman parameters are encoded using the "DH PARAMETERS" label
   error = pemDecodeFile(input, length, "DH PARAMETERS", NULL, &n, NULL, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the ASN.1 data
      buffer = cryptoAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the PEM container
         error = pemDecodeFile(input, length, "DH PARAMETERS", buffer, &n,
            NULL, NULL);

         //Check status code
         if(!error)
         {
            //The Diffie-Hellman parameters are encapsulated within a sequence
            error = asn1ReadSequence(buffer, n, &tag);
         }

         //Check status code
         if(!error)
         {
            //Point to the first field of the sequence
            p = tag.value;
            n = tag.length;

            //Read the prime modulus
            error = asn1ReadMpi(p, n, &tag, &params->p);
         }

         //Check status code
         if(!error)
         {
            //Point to the next field
            p += tag.totalLength;
            n -= tag.totalLength;

            //Read the generator
            error = asn1ReadMpi(p, n, &tag, &params->g);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("Diffie-Hellman parameters:\r\n");
            TRACE_DEBUG("  Prime modulus:\r\n");
            TRACE_DEBUG_MPI("    ", &params->p);
            TRACE_DEBUG("  Generator:\r\n");
            TRACE_DEBUG_MPI("    ", &params->g);
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

#endif
