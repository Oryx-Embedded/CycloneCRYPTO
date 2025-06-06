/**
 * @file ocsp_req_create.c
 * @brief OCSP request generation
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
#define TRACE_LEVEL OCSP_TRACE_LEVEL

//Dependencies
#include "ocsp/ocsp_req_create.h"
#include "ocsp/ocsp_req_format.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (OCSP_SUPPORT == ENABLED)


/**
 * @brief Generate an OCSP request
 * @param[in] certInfo Certificate to be checked
 * @param[in] issuerCertInfo Issuer's certificate
 * @param[in] nonce Pointer to the random nonce (optional parameter)
 * @param[in] nonceLen Length of the nonce, in bytes (optional parameter)
 * @param[out] output Buffer where to store the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t ocspCreateRequest(const X509CertInfo *certInfo,
   const X509CertInfo *issuerCertInfo, const uint8_t *nonce,
   size_t nonceLen, uint8_t *output, size_t *written)
{
   error_t error;
   size_t n;
   OcspRequest request;
   OcspCertId *certId;
   const HashAlgo *hashAlgo;
   const X509SubjectPublicKeyInfo *issuerPublicKeyInfo;
   uint8_t issuerNameHash[MAX_HASH_DIGEST_SIZE];
   uint8_t issuerKeyHash[MAX_HASH_DIGEST_SIZE];

   //Clear OCSPRequest structure
   osMemset(&request, 0, sizeof(OcspRequest));

   //Set the version of the protocol
   request.tbsRequest.version = OCSP_VERSION_1;

   //OCSP requests conformant to this profile must include only one request
   //in the RequestList structure (refer to RFC 5019, section 2.1.1)
   request.tbsRequest.numRequests = 1;

   //Point to the certificate identifier
   certId = &request.tbsRequest.requestList[0].reqCert;

   //Select the relevant hash algorithm that will be used to generate the
   //IssuerNameHash and IssuerKeyHash values
   hashAlgo = ocspSelectHashAlgo();
   //Invalid hash algorithm?
   if(hashAlgo == NULL)
      return ERROR_UNSUPPORTED_HASH_ALGO;

   //Digest the DER encoding of the issuer's name field in the certificate
   //being checked (refer to RFC 6960, section 4.1.1)
   error = hashAlgo->compute(certInfo->tbsCert.issuer.raw.value,
      certInfo->tbsCert.issuer.raw.length, issuerNameHash);
   //Any error to report?
   if(error)
      return error;

   //Point to the issuer's public key
   issuerPublicKeyInfo = &issuerCertInfo->tbsCert.subjectPublicKeyInfo;

   //Digest the value (excluding tag and length) of the subject public key
   //field in the issuer's certificate
   error = hashAlgo->compute(issuerPublicKeyInfo->rawSubjectPublicKey.value,
      issuerPublicKeyInfo->rawSubjectPublicKey.length, issuerKeyHash);
   //Any error to report?
   if(error)
      return error;

   //Set hash algorithm OID
   certId->hashAlgo.value = hashAlgo->oid;
   certId->hashAlgo.length = hashAlgo->oidSize;

   //Set the hash of the issuer's distinguished name (DN)
   certId->issuerNameHash.value = issuerNameHash;
   certId->issuerNameHash.length = hashAlgo->digestSize;

   //Set the hash of the issuer's public key
   certId->issuerKeyHash.value = issuerKeyHash;
   certId->issuerKeyHash.length = hashAlgo->digestSize;

   //Specify the serial number of the certificate for which status is being
   //requested
   certId->serialNumber.value = certInfo->tbsCert.serialNumber.value;
   certId->serialNumber.length = certInfo->tbsCert.serialNumber.length;

   //The Nonce extension is used to cryptographically binds a request and a
   //response to prevent replay attacks (refer to RFC 8954, section 2.1)
   request.tbsRequest.requestExtensions.nonce.value = nonce;
   request.tbsRequest.requestExtensions.nonce.length = nonceLen;

   //Format OCSPRequest structure
   error = ocspFormatRequest(&request, output, &n);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("OCSP request (%" PRIuSIZE " bytes):\r\n", n);
   //Dump OCSP request
   asn1DumpObject(output, n, 0);

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}

#endif
