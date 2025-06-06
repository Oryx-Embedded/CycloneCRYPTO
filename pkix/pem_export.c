/**
 * @file pem_export.c
 * @brief PEM file export functions
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
#include "pkix/pem_export.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Export an X.509 certificate to PEM format
 * @param[in] cert Pointer to the DER-encoded certificate
 * @param[in] certLen Length of the DER-encoded certificate, in bytes
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @return Error code
 **/

error_t pemExportCertificate(const uint8_t *cert, size_t certLen,
   char_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(cert == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //X.509 certificates are encoded using the "CERTIFICATE" label
   error = pemEncodeFile(cert, certLen, "CERTIFICATE", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export a certificate revocation list to PEM format
 * @param[in] crl Pointer to the DER-encoded CRL
 * @param[in] crlLen Length of the DER-encoded CRL, in bytes
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @return Error code
 **/

error_t pemExportCrl(const uint8_t *crl, size_t crlLen,
   char_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(crl == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //CRLs are encoded using the "X509 CRL" label
   error = pemEncodeFile(crl, crlLen, "X509 CRL", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export a certification signing request to PEM format
 * @param[in] csr Pointer to the DER-encoded CSR
 * @param[in] csrLen Length of the DER-encoded CSR, in bytes
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @return Error code
 **/

error_t pemExportCsr(const uint8_t *csr, size_t csrLen,
   char_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(csr == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //CSRs are encoded using the "CERTIFICATE REQUEST" label
   error = pemEncodeFile(csr, csrLen, "CERTIFICATE REQUEST", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export EC domain parameters to PEM format
 * @param[in] curve Elliptic curve parameters
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @return Error code
 **/

error_t pemExportEcParameters(const EcCurve *curve, char_t *output,
   size_t *written)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Check parameters
   if(curve == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format ECParameters field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = curve->oidSize;
   tag.value = curve->oid;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //EC domain parameters are encoded using the "EC PARAMETERS" label
   error = pemEncodeFile(output, n, "EC PARAMETERS", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
