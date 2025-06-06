/**
 * @file pkcs7_common.h
 * @brief PKCS #7 common definitions
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

#ifndef _PKCS7_COMMON_H
#define _PKCS7_COMMON_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//DES encryption support (insecure)
#ifndef PKCS7_DES_SUPPORT
   #define PKCS7_DES_SUPPORT DISABLED
#elif (PKCS7_DES_SUPPORT != ENABLED && PKCS7_DES_SUPPORT != DISABLED)
   #error PKCS7_DES_SUPPORT parameter is not valid
#endif

//Triple DES encryption support (weak)
#ifndef PKCS7_3DES_SUPPORT
   #define PKCS7_3DES_SUPPORT DISABLED
#elif (PKCS7_3DES_SUPPORT != ENABLED && PKCS7_3DES_SUPPORT != DISABLED)
   #error PKCS7_3DES_SUPPORT parameter is not valid
#endif

//AES encryption support
#ifndef PKCS7_AES_SUPPORT
   #define PKCS7_AES_SUPPORT ENABLED
#elif (PKCS7_AES_SUPPORT != ENABLED && PKCS7_AES_SUPPORT != DISABLED)
   #error PKCS7_AES_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef PKCS7_MD5_SUPPORT
   #define PKCS7_MD5_SUPPORT DISABLED
#elif (PKCS7_MD5_SUPPORT != ENABLED && PKCS7_MD5_SUPPORT != DISABLED)
   #error PKCS7_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef PKCS7_SHA1_SUPPORT
   #define PKCS7_SHA1_SUPPORT DISABLED
#elif (PKCS7_SHA1_SUPPORT != ENABLED && PKCS7_SHA1_SUPPORT != DISABLED)
   #error PKCS7_SHA1_SUPPORT parameter is not valid
#endif

//SHA-224 hash support (weak)
#ifndef PKCS7_SHA224_SUPPORT
   #define PKCS7_SHA224_SUPPORT DISABLED
#elif (PKCS7_SHA224_SUPPORT != ENABLED && PKCS7_SHA224_SUPPORT != DISABLED)
   #error PKCS7_SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef PKCS7_SHA256_SUPPORT
   #define PKCS7_SHA256_SUPPORT ENABLED
#elif (PKCS7_SHA256_SUPPORT != ENABLED && PKCS7_SHA256_SUPPORT != DISABLED)
   #error PKCS7_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef PKCS7_SHA384_SUPPORT
   #define PKCS7_SHA384_SUPPORT ENABLED
#elif (PKCS7_SHA384_SUPPORT != ENABLED && PKCS7_SHA384_SUPPORT != DISABLED)
   #error PKCS7_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef PKCS7_SHA512_SUPPORT
   #define PKCS7_SHA512_SUPPORT ENABLED
#elif (PKCS7_SHA512_SUPPORT != ENABLED && PKCS7_SHA512_SUPPORT != DISABLED)
   #error PKCS7_SHA512_SUPPORT parameter is not valid
#endif

//RSA signature support
#ifndef PKCS7_RSA_SUPPORT
   #define PKCS7_RSA_SUPPORT ENABLED
#elif (PKCS7_RSA_SUPPORT != ENABLED && PKCS7_RSA_SUPPORT != DISABLED)
   #error PKCS7_RSA_SUPPORT parameter is not valid
#endif

//Maximum number of digest algorithm identifiers
#ifndef PKCS7_MAX_DIGEST_ALGO_IDENTIFIERS
   #define PKCS7_MAX_DIGEST_ALGO_IDENTIFIERS 2
#elif (PKCS7_MAX_DIGEST_ALGO_IDENTIFIERS < 1)
   #error PKCS7_MAX_DIGEST_ALGO_IDENTIFIERS parameter is not valid
#endif

//Maximum number of certificates
#ifndef PKCS7_MAX_CERTIFICATES
   #define PKCS7_MAX_CERTIFICATES 4
#elif (PKCS7_MAX_CERTIFICATES < 1)
   #error PKCS7_MAX_CERTIFICATES parameter is not valid
#endif

//Maximum number of CRLs
#ifndef PKCS7_MAX_CRLS
   #define PKCS7_MAX_CRLS 4
#elif (PKCS7_MAX_CRLS < 1)
   #error PKCS7_MAX_CRLS parameter is not valid
#endif

//Maximum number of signer informations
#ifndef PKCS7_MAX_SIGNER_INFOS
   #define PKCS7_MAX_SIGNER_INFOS 2
#elif (PKCS7_MAX_SIGNER_INFOS < 1)
   #error PKCS7_MAX_SIGNER_INFOS parameter is not valid
#endif

//Maximum number of recipient informations
#ifndef PKCS7_MAX_RECIPIENT_INFOS
   #define PKCS7_MAX_RECIPIENT_INFOS 2
#elif (PKCS7_MAX_RECIPIENT_INFOS < 1)
   #error PKCS7_MAX_RECIPIENT_INFOS parameter is not valid
#endif

//Maximum number of custom attributes
#ifndef PKCS7_MAX_CUSTOM_ATTRIBUTES
   #define PKCS7_MAX_CUSTOM_ATTRIBUTES 4
#elif (PKCS7_MAX_CUSTOM_ATTRIBUTES < 1)
   #error PKCS7_MAX_CUSTOM_ATTRIBUTES parameter is not valid
#endif

//Maximum key size for encryption algorithms
#define PKCS7_MAX_ENCR_KEY_SIZE 32

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Syntax version number
 **/

typedef enum
{
   PKCS7_VERSION_0 = 0, ///<v0
   PKCS7_VERSION_1 = 1, ///<v1
   PKCS7_VERSION_2 = 2, ///<v2
   PKCS7_VERSION_3 = 3, ///<v3
   PKCS7_VERSION_4 = 4, ///<v4
   PKCS7_VERSION_5 = 5  ///<v5
} Pkcs7Version;


/**
 * @brief Collection of digest algorithm identifiers
 **/

typedef struct
{
   uint_t numIdentifiers;
   X509AlgoId identifiers[PKCS7_MAX_DIGEST_ALGO_IDENTIFIERS];
} Pkcs7DigestAlgos;


/**
 * @brief Collection of certificates
 **/

typedef struct
{
   X509OctetString raw;
   uint_t numCertificates;
   X509OctetString certificates[PKCS7_MAX_CERTIFICATES];
} Pkcs7Certificates;


/**
 * @brief Collection of CRLs
 **/

typedef struct
{
   X509OctetString raw;
   uint_t numCrls;
   X509OctetString crls[PKCS7_MAX_CRLS];
} Pkcs7Crls;


/**
 * @brief Issuer and serial number
 **/

typedef struct
{
   X509Name name;
   X509SerialNumber serialNumber;
} Pkcs7IssuerAndSerialNumber;


/**
 * @brief Attribute
 **/

typedef struct
{
   X509OctetString oid;
   uint_t type;
   X509OctetString data;
} Pkcs7Attribute;


/**
 * @brief Authenticated attributes
 **/

typedef struct
{
   X509OctetString raw;
   X509OctetString contentType;
   X509OctetString messageDigest;
   DateTime signingTime;
   uint_t numCustomAttributes;
   Pkcs7Attribute customAttributes[PKCS7_MAX_CUSTOM_ATTRIBUTES];
} Pkcs7AuthenticatedAttributes;


/**
 * @brief Unauthenticated attributes
 **/

typedef struct
{
   X509OctetString raw;
   uint_t numCustomAttributes;
   Pkcs7Attribute customAttributes[PKCS7_MAX_CUSTOM_ATTRIBUTES];
} Pkcs7UnauthenticatedAttributes;


/**
 * @brief Signer information
 **/

typedef struct
{
   int32_t version;
   Pkcs7IssuerAndSerialNumber issuerAndSerialNumber;
   X509AlgoId digestAlgo;
   Pkcs7AuthenticatedAttributes authenticatedAttributes;
   X509SignAlgoId digestEncryptionAlgo;
   X509OctetString encryptedDigest;
   Pkcs7UnauthenticatedAttributes unauthenticatedAttributes;
} Pkcs7SignerInfo;


/**
 * @brief Collection of signer informations
 **/

typedef struct
{
   X509OctetString raw;
   uint_t numSignerInfos;
   Pkcs7SignerInfo signerInfos[PKCS7_MAX_SIGNER_INFOS];
} Pkcs7SignerInfos;


/**
 * @brief Recipient information
 **/

typedef struct
{
   int32_t version;
   Pkcs7IssuerAndSerialNumber issuerAndSerialNumber;
   X509AlgoId keyEncryptionAlgo;
   X509OctetString encryptedKey;
} Pkcs7RecipientInfo;


/**
 * @brief Collection of recipient informations
 **/

typedef struct
{
   X509OctetString raw;
   uint_t numRecipientInfos;
   Pkcs7RecipientInfo recipientInfos[PKCS7_MAX_RECIPIENT_INFOS];
} Pkcs7RecipientInfos;


/**
 * @brief Content information
 **/

typedef struct
{
   X509OctetString contentType;
   X509OctetString content;
} Pkcs7ContentInfo;


/**
 * @brief Content encryption algorithm
 **/

typedef struct
{
   X509OctetString oid;
   X509OctetString iv;
} Pkcs7ContentEncrAlgo;


/**
 * @brief Encrypted content information
 **/

typedef struct
{
   X509OctetString contentType;
   Pkcs7ContentEncrAlgo contentEncrAlgo;
   X509OctetString encryptedContent;
} Pkcs7EncryptedContentInfo;


/**
 * @brief Signed data content
 **/

typedef struct
{
   int32_t version;
   Pkcs7DigestAlgos digestAlgos;
   Pkcs7ContentInfo contentInfo;
   Pkcs7Certificates certificates;
   Pkcs7Crls crls;
   Pkcs7SignerInfos signerInfos;
} Pkcs7SignedData;


/**
 * @brief Enveloped data content
 **/

typedef struct
{
   int32_t version;
   Pkcs7RecipientInfos recipientInfos;
   Pkcs7EncryptedContentInfo encryptedContentInfo;
} Pkcs7EnvelopedData;


//PKCS #7 related constants
extern const uint8_t PKCS7_OID[8];
extern const uint8_t PKCS7_DATA_OID[9];
extern const uint8_t PKCS7_SIGNED_DATA_OID[9];
extern const uint8_t PKCS7_ENVELOPED_DATA_OID[9];
extern const uint8_t PKCS7_SIGNED_AND_ENVELOPED_DATA_OID[9];
extern const uint8_t PKCS7_DIGESTED_DATA_OID[9];
extern const uint8_t PKCS7_ENCRYPTED_DATA_OID[9];

extern const uint8_t PKCS9_CONTENT_TYPE_OID[9];
extern const uint8_t PKCS9_MESSAGE_DIGEST_OID[9];
extern const uint8_t PKCS9_SIGNING_TIME_OID[9];

//PKCS #7 related functions
const HashAlgo *pkcs7GetHashAlgo(const uint8_t *oid, size_t length);
const HashAlgo *pkcs7GetSignHashAlgo(const uint8_t *oid, size_t length);

const CipherAlgo *pkcs7GetCipherAlgo(const uint8_t *oid, size_t length);
uint_t pkcs7GetKeyLength(const uint8_t *oid, size_t length);

int_t pkcs7CompAttributes(const uint8_t *attribute1, size_t attributeLen1,
   const uint8_t *attribute2, size_t attributeLen2);

error_t pkcs7DigestAuthenticatedAttributes(const Pkcs7SignerInfo *signerInfo,
   const uint8_t *data, size_t length, uint8_t *digest);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
