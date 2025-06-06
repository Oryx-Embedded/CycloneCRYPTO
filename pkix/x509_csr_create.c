/**
 * @file x509_csr_create.c
 * @brief CSR (Certificate Signing Request) generation
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
#include "pkix/x509_csr_create.h"
#include "pkix/x509_csr_format.h"
#include "pkix/x509_sign_format.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief Generate a CSR (Certificate Signing Request)
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] certReqInfo Certificate request information
 * @param[in] subjectPublicKey Pointer to the subject's public key
 * @param[in] signatureAlgo Signature algorithm
 * @param[in] signerPrivateKey Pointer to the subject's private key
 * @param[out] output Buffer where to store the CSR
 * @param[out] written Length of the resulting CSR
 * @return Error code
 **/

error_t x509CreateCsr(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertRequestInfo *certReqInfo, const void *subjectPublicKey,
   const X509SignAlgoId *signatureAlgo, const void *signerPrivateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   X509OctetString tbsData;
   Asn1Tag tag;

   //Check parameters
   if(certReqInfo == NULL || subjectPublicKey == NULL ||
      signatureAlgo == NULL || signerPrivateKey == NULL || written == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Point to the buffer where to write the CSR
   p = output;
   //Length of the CSR
   length = 0;

   //Format CertificationRequestInfo structure
   error = x509FormatCertRequestInfo(certReqInfo, subjectPublicKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //The ASN.1 DER-encoded CertificationRequestInfo is used as the input to
   //the signature function
   tbsData.value = p;
   tbsData.length = n;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format SignatureAlgorithm structure
   error = x509FormatSignatureAlgo(signatureAlgo, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //Format Signature structure
   error = x509FormatSignatureValue(prngAlgo, prngContext, &tbsData,
      signatureAlgo, &certReqInfo->subjectPublicKeyInfo, signerPrivateKey,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance data pointer
   ASN1_INC_POINTER(p, n);
   length += n;

   //The CSR is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;

   //Write the corresponding ASN.1 tag
   error = asn1InsertHeader(&tag, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = tag.totalLength;

   //Successful processing
   return NO_ERROR;
}

#endif
