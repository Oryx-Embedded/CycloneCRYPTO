/**
 * @file ocsp_common.h
 * @brief OCSP common definitions
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

#ifndef _OCSP_COMMON_H
#define _OCSP_COMMON_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//OCSP support
#ifndef OCSP_SUPPORT
   #define OCSP_SUPPORT DISABLED
#elif (OCSP_SUPPORT != ENABLED && OCSP_SUPPORT != DISABLED)
   #error OCSP_SUPPORT parameter is not valid
#endif

//OCSP signature authority delegation support
#ifndef OCSP_SIGN_DELEGATION_SUPPORT
   #define OCSP_SIGN_DELEGATION_SUPPORT ENABLED
#elif (OCSP_SIGN_DELEGATION_SUPPORT != ENABLED && OCSP_SIGN_DELEGATION_SUPPORT != DISABLED)
   #error OCSP_SIGN_DELEGATION_SUPPORT parameter is not valid
#endif

//Maximum number of requests per OCSP request
#ifndef OCSP_MAX_REQUESTS
   #define OCSP_MAX_REQUESTS 2
#elif (OCSP_MAX_REQUESTS < 1)
   #error OCSP_MAX_REQUESTS parameter is not valid
#endif

//Maximum number of responses per OCSP response
#ifndef OCSP_MAX_RESPONSES
   #define OCSP_MAX_RESPONSES 2
#elif (OCSP_MAX_RESPONSES < 1)
   #error OCSP_MAX_RESPONSES parameter is not valid
#endif

//SHA-1 hash support
#ifndef OCSP_SHA1_SUPPORT
   #define OCSP_SHA1_SUPPORT ENABLED
#elif (OCSP_SHA1_SUPPORT != ENABLED && OCSP_SHA1_SUPPORT != DISABLED)
   #error OCSP_SHA1_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef OCSP_SHA256_SUPPORT
   #define OCSP_SHA256_SUPPORT ENABLED
#elif (OCSP_SHA256_SUPPORT != ENABLED && OCSP_SHA256_SUPPORT != DISABLED)
   #error OCSP_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef OCSP_SHA384_SUPPORT
   #define OCSP_SHA384_SUPPORT DISABLED
#elif (OCSP_SHA384_SUPPORT != ENABLED && OCSP_SHA384_SUPPORT != DISABLED)
   #error OCSP_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef OCSP_SHA512_SUPPORT
   #define OCSP_SHA512_SUPPORT DISABLED
#elif (OCSP_SHA512_SUPPORT != ENABLED && OCSP_SHA512_SUPPORT != DISABLED)
   #error OCSP_SHA512_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief OCSP versions
 **/

typedef enum
{
   OCSP_VERSION_1 = 0
} OcspVersion;


/**
 * @brief OCSP response status
 **/

typedef enum
{
   OCSP_RESP_STATUS_SUCCESSFUL        = 0, ///<Response has valid confirmations
   OCSP_RESP_STATUS_MALFORMED_REQUEST = 1, ///<Illegal confirmation request
   OCSP_RESP_STATUS_INTERNAL_ERROR    = 2, ///<Internal error in issuer
   OCSP_RESP_STATUS_TRY_LATER         = 3, ///<Try again later
   OCSP_RESP_STATUS_SIG_REQUIRED      = 5, ///<Must sign the request
   OCSP_RESP_STATUS_UNAUTHORIZED      = 6  ///<Request unauthorized
} OcspResponseStatus;


/**
 * @brief Certificate status
 **/

typedef enum
{
   OCSP_CERT_STATUS_GOOD    = 0,
   OCSP_CERT_STATUS_REVOKED = 1,
   OCSP_CERT_STATUS_UNKNOWN = 2
} OcspCertStatus;


/**
 * @brief CertID structure
 **/

typedef struct
{
   X509OctetString hashAlgo;
   X509OctetString issuerNameHash;
   X509OctetString issuerKeyHash;
   X509OctetString serialNumber;
} OcspCertId;


/**
 * @brief Single request/response extensions
 **/

typedef struct
{
   X509OctetString raw;
} OcspSingleExtensions;


/**
 * @brief SingleRequest structure
 **/

typedef struct
{
   OcspCertId reqCert;
   OcspSingleExtensions singleExtensions;
} OcspSingleRequest;


/**
 * @brief OCSP extensions
 **/

typedef struct
{
   X509OctetString raw;
   X509OctetString nonce;
} OcspExtensions;


/**
 * @brief TBSRequest structure
 **/

typedef struct
{
   OcspVersion version;
   uint_t numRequests;
   OcspSingleRequest requestList[OCSP_MAX_REQUESTS];
   OcspExtensions requestExtensions;
} OcspTbsRequest;


/**
 * @brief OCSPRequest structure
 **/

typedef struct
{
   OcspTbsRequest tbsRequest;
   X509SignAlgoId signatureAlgo;
   X509OctetString signatureValue;
} OcspRequest;


/**
 * @brief RevokedInfo structure
 **/

typedef struct
{
   DateTime revocationTime;
   X509CrlReasons revocationReason;
} OcspRevokedInfo;


/**
 * @brief SingleResponse structure
 **/

typedef struct
{
   OcspCertId certId;
   OcspCertStatus certStatus;
   OcspRevokedInfo revokedInfo;
   DateTime thisUpdate;
   DateTime nextUpdate;
   OcspSingleExtensions singleExtensions;
} OcspSingleResponse;


/**
 * @brief ResponderID structure
 **/

typedef struct
{
   X509Name name;
   X509OctetString keyHash;
} OcspResponderId;


/**
 * @brief TbsResponseData structure
 **/

typedef struct
{
   X509OctetString raw;
   OcspVersion version;
   OcspResponderId responderId;
   DateTime producedAt;
   uint_t numResponses;
   OcspSingleResponse responses[OCSP_MAX_RESPONSES];
   OcspExtensions responseExtensions;
} OcspTbsResponseData;


/**
 * @brief OcspCerts structure
 **/

typedef struct
{
   X509OctetString raw;
} OcspCerts;


/**
 * @brief BasicOCSPResponse structure
 **/

typedef struct
{
   OcspTbsResponseData tbsResponseData;
   X509SignAlgoId signatureAlgo;
   X509OctetString signature;
   OcspCerts certs;
} OcspBasicResponse;


/**
 * @brief OCSPResponse structure
 **/

typedef struct
{
   X509OctetString raw;
   OcspResponseStatus responseStatus;
   X509OctetString responseType;
   OcspBasicResponse basicResponse;
} OcspResponse;


//OCSP related constants
extern const uint8_t PKIX_OCSP_BASIC_OID[9];
extern const uint8_t PKIX_OCSP_NONCE_OID[9];

//OCSP related functions
const HashAlgo *ocspSelectHashAlgo(void);
const HashAlgo *ocspGetHashAlgo(const uint8_t *oid, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
