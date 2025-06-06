/**
 * @file x509_common.h
 * @brief X.509 common definitions
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

#ifndef _X509_COMMON_H
#define _X509_COMMON_H

//Dependencies
#include "core/crypto.h"
#include "pkc/sign_algorithms.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "ecc/eddsa.h"
#include "date_time.h"

//Signature generation/verification callback functions
#ifndef X509_SIGN_CALLBACK_SUPPORT
   #define X509_SIGN_CALLBACK_SUPPORT DISABLED
#elif (X509_SIGN_CALLBACK_SUPPORT != ENABLED && X509_SIGN_CALLBACK_SUPPORT != DISABLED)
   #error X509_SIGN_CALLBACK_SUPPORT parameter is not valid
#endif

//RSA certificate support
#ifndef X509_RSA_SUPPORT
   #define X509_RSA_SUPPORT ENABLED
#elif (X509_RSA_SUPPORT != ENABLED && X509_RSA_SUPPORT != DISABLED)
   #error X509_RSA_SUPPORT parameter is not valid
#endif

//RSA-PSS certificate support
#ifndef X509_RSA_PSS_SUPPORT
   #define X509_RSA_PSS_SUPPORT DISABLED
#elif (X509_RSA_PSS_SUPPORT != ENABLED && X509_RSA_PSS_SUPPORT != DISABLED)
   #error X509_RSA_PSS_SUPPORT parameter is not valid
#endif

//DSA certificate support
#ifndef X509_DSA_SUPPORT
   #define X509_DSA_SUPPORT DISABLED
#elif (X509_DSA_SUPPORT != ENABLED && X509_DSA_SUPPORT != DISABLED)
   #error X509_DSA_SUPPORT parameter is not valid
#endif

//ECDSA certificate support
#ifndef X509_ECDSA_SUPPORT
   #define X509_ECDSA_SUPPORT ENABLED
#elif (X509_ECDSA_SUPPORT != ENABLED && X509_ECDSA_SUPPORT != DISABLED)
   #error X509_ECDSA_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef X509_MD5_SUPPORT
   #define X509_MD5_SUPPORT DISABLED
#elif (X509_MD5_SUPPORT != ENABLED && X509_MD5_SUPPORT != DISABLED)
   #error X509_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef X509_SHA1_SUPPORT
   #define X509_SHA1_SUPPORT DISABLED
#elif (X509_SHA1_SUPPORT != ENABLED && X509_SHA1_SUPPORT != DISABLED)
   #error X509_SHA1_SUPPORT parameter is not valid
#endif

//SHA-224 hash support (weak)
#ifndef X509_SHA224_SUPPORT
   #define X509_SHA224_SUPPORT DISABLED
#elif (X509_SHA224_SUPPORT != ENABLED && X509_SHA224_SUPPORT != DISABLED)
   #error X509_SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef X509_SHA256_SUPPORT
   #define X509_SHA256_SUPPORT ENABLED
#elif (X509_SHA256_SUPPORT != ENABLED && X509_SHA256_SUPPORT != DISABLED)
   #error X509_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef X509_SHA384_SUPPORT
   #define X509_SHA384_SUPPORT ENABLED
#elif (X509_SHA384_SUPPORT != ENABLED && X509_SHA384_SUPPORT != DISABLED)
   #error X509_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef X509_SHA512_SUPPORT
   #define X509_SHA512_SUPPORT ENABLED
#elif (X509_SHA512_SUPPORT != ENABLED && X509_SHA512_SUPPORT != DISABLED)
   #error X509_SHA512_SUPPORT parameter is not valid
#endif

//SHA3-224 hash support
#ifndef X509_SHA3_224_SUPPORT
   #define X509_SHA3_224_SUPPORT DISABLED
#elif (X509_SHA3_224_SUPPORT != ENABLED && X509_SHA3_224_SUPPORT != DISABLED)
   #error X509_SHA3_224_SUPPORT parameter is not valid
#endif

//SHA3-256 hash support
#ifndef X509_SHA3_256_SUPPORT
   #define X509_SHA3_256_SUPPORT DISABLED
#elif (X509_SHA3_256_SUPPORT != ENABLED && X509_SHA3_256_SUPPORT != DISABLED)
   #error X509_SHA3_256_SUPPORT parameter is not valid
#endif

//SHA3-384 hash support
#ifndef X509_SHA3_384_SUPPORT
   #define X509_SHA3_384_SUPPORT DISABLED
#elif (X509_SHA3_384_SUPPORT != ENABLED && X509_SHA3_384_SUPPORT != DISABLED)
   #error X509_SHA3_384_SUPPORT parameter is not valid
#endif

//SHA3-512 hash support
#ifndef X509_SHA3_512_SUPPORT
   #define X509_SHA3_512_SUPPORT DISABLED
#elif (X509_SHA3_512_SUPPORT != ENABLED && X509_SHA3_512_SUPPORT != DISABLED)
   #error X509_SHA3_512_SUPPORT parameter is not valid
#endif

//SM3 hash support
#ifndef X509_SM3_SUPPORT
   #define X509_SM3_SUPPORT DISABLED
#elif (X509_SM3_SUPPORT != ENABLED && X509_SM3_SUPPORT != DISABLED)
   #error X509_SM3_SUPPORT parameter is not valid
#endif

//secp112r1 elliptic curve support (weak)
#ifndef X509_SECP112R1_SUPPORT
   #define X509_SECP112R1_SUPPORT DISABLED
#elif (X509_SECP112R1_SUPPORT != ENABLED && X509_SECP112R1_SUPPORT != DISABLED)
   #error X509_SECP112R1_SUPPORT parameter is not valid
#endif

//secp112r2 elliptic curve support (weak)
#ifndef X509_SECP112R2_SUPPORT
   #define X509_SECP112R2_SUPPORT DISABLED
#elif (X509_SECP112R2_SUPPORT != ENABLED && X509_SECP112R2_SUPPORT != DISABLED)
   #error X509_SECP112R2_SUPPORT parameter is not valid
#endif

//secp128r1 elliptic curve support (weak)
#ifndef X509_SECP128R1_SUPPORT
   #define X509_SECP128R1_SUPPORT DISABLED
#elif (X509_SECP128R1_SUPPORT != ENABLED && X509_SECP128R1_SUPPORT != DISABLED)
   #error X509_SECP128R1_SUPPORT parameter is not valid
#endif

//secp128r2 elliptic curve support (weak)
#ifndef X509_SECP128R2_SUPPORT
   #define X509_SECP128R2_SUPPORT DISABLED
#elif (X509_SECP128R2_SUPPORT != ENABLED && X509_SECP128R2_SUPPORT != DISABLED)
   #error X509_SECP128R2_SUPPORT parameter is not valid
#endif

//secp160k1 elliptic curve support (weak)
#ifndef X509_SECP160K1_SUPPORT
   #define X509_SECP160K1_SUPPORT DISABLED
#elif (X509_SECP160K1_SUPPORT != ENABLED && X509_SECP160K1_SUPPORT != DISABLED)
   #error X509_SECP160K1_SUPPORT parameter is not valid
#endif

//secp160r1 elliptic curve support (weak)
#ifndef X509_SECP160R1_SUPPORT
   #define X509_SECP160R1_SUPPORT DISABLED
#elif (X509_SECP160R1_SUPPORT != ENABLED && X509_SECP160R1_SUPPORT != DISABLED)
   #error X509_SECP160R1_SUPPORT parameter is not valid
#endif

//secp160r2 elliptic curve support (weak)
#ifndef X509_SECP160R2_SUPPORT
   #define X509_SECP160R2_SUPPORT DISABLED
#elif (X509_SECP160R2_SUPPORT != ENABLED && X509_SECP160R2_SUPPORT != DISABLED)
   #error X509_SECP160R2_SUPPORT parameter is not valid
#endif

//secp192k1 elliptic curve support
#ifndef X509_SECP192K1_SUPPORT
   #define X509_SECP192K1_SUPPORT DISABLED
#elif (X509_SECP192K1_SUPPORT != ENABLED && X509_SECP192K1_SUPPORT != DISABLED)
   #error X509_SECP192K1_SUPPORT parameter is not valid
#endif

//secp192r1 elliptic curve support (NIST P-192)
#ifndef X509_SECP192R1_SUPPORT
   #define X509_SECP192R1_SUPPORT DISABLED
#elif (X509_SECP192R1_SUPPORT != ENABLED && X509_SECP192R1_SUPPORT != DISABLED)
   #error X509_SECP192R1_SUPPORT parameter is not valid
#endif

//secp224k1 elliptic curve support
#ifndef X509_SECP224K1_SUPPORT
   #define X509_SECP224K1_SUPPORT DISABLED
#elif (X509_SECP224K1_SUPPORT != ENABLED && X509_SECP224K1_SUPPORT != DISABLED)
   #error X509_SECP224K1_SUPPORT parameter is not valid
#endif

//secp224r1 elliptic curve support (NIST P-224)
#ifndef X509_SECP224R1_SUPPORT
   #define X509_SECP224R1_SUPPORT DISABLED
#elif (X509_SECP224R1_SUPPORT != ENABLED && X509_SECP224R1_SUPPORT != DISABLED)
   #error X509_SECP224R1_SUPPORT parameter is not valid
#endif

//secp256k1 elliptic curve support
#ifndef X509_SECP256K1_SUPPORT
   #define X509_SECP256K1_SUPPORT DISABLED
#elif (X509_SECP256K1_SUPPORT != ENABLED && X509_SECP256K1_SUPPORT != DISABLED)
   #error X509_SECP256K1_SUPPORT parameter is not valid
#endif

//secp256r1 elliptic curve support (NIST P-256)
#ifndef X509_SECP256R1_SUPPORT
   #define X509_SECP256R1_SUPPORT ENABLED
#elif (X509_SECP256R1_SUPPORT != ENABLED && X509_SECP256R1_SUPPORT != DISABLED)
   #error X509_SECP256R1_SUPPORT parameter is not valid
#endif

//secp384r1 elliptic curve support (NIST P-384)
#ifndef X509_SECP384R1_SUPPORT
   #define X509_SECP384R1_SUPPORT ENABLED
#elif (X509_SECP384R1_SUPPORT != ENABLED && X509_SECP384R1_SUPPORT != DISABLED)
   #error X509_SECP384R1_SUPPORT parameter is not valid
#endif

//secp521r1 elliptic curve support (NIST P-521)
#ifndef X509_SECP521R1_SUPPORT
   #define X509_SECP521R1_SUPPORT ENABLED
#elif (X509_SECP521R1_SUPPORT != ENABLED && X509_SECP521R1_SUPPORT != DISABLED)
   #error X509_SECP521R1_SUPPORT parameter is not valid
#endif

//brainpoolP160r1 elliptic curve support
#ifndef X509_BRAINPOOLP160R1_SUPPORT
   #define X509_BRAINPOOLP160R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP160R1_SUPPORT != ENABLED && X509_BRAINPOOLP160R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP160R1_SUPPORT parameter is not valid
#endif

//brainpoolP160t1 elliptic curve support
#ifndef X509_BRAINPOOLP160T1_SUPPORT
   #define X509_BRAINPOOLP160T1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP160T1_SUPPORT != ENABLED && X509_BRAINPOOLP160T1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP160T1_SUPPORT parameter is not valid
#endif

//brainpoolP192r1 elliptic curve support
#ifndef X509_BRAINPOOLP192R1_SUPPORT
   #define X509_BRAINPOOLP192R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP192R1_SUPPORT != ENABLED && X509_BRAINPOOLP192R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP192R1_SUPPORT parameter is not valid
#endif

//brainpoolP192t1 elliptic curve support
#ifndef X509_BRAINPOOLP192T1_SUPPORT
   #define X509_BRAINPOOLP192T1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP192T1_SUPPORT != ENABLED && X509_BRAINPOOLP192T1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP192T1_SUPPORT parameter is not valid
#endif

//brainpoolP224r1 elliptic curve support
#ifndef X509_BRAINPOOLP224R1_SUPPORT
   #define X509_BRAINPOOLP224R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP224R1_SUPPORT != ENABLED && X509_BRAINPOOLP224R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP224R1_SUPPORT parameter is not valid
#endif

//brainpoolP224t1 elliptic curve support
#ifndef X509_BRAINPOOLP224T1_SUPPORT
   #define X509_BRAINPOOLP224T1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP224T1_SUPPORT != ENABLED && X509_BRAINPOOLP224T1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP224T1_SUPPORT parameter is not valid
#endif

//brainpoolP256r1 elliptic curve support
#ifndef X509_BRAINPOOLP256R1_SUPPORT
   #define X509_BRAINPOOLP256R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP256R1_SUPPORT != ENABLED && X509_BRAINPOOLP256R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP256R1_SUPPORT parameter is not valid
#endif

//brainpoolP256t1 elliptic curve support
#ifndef X509_BRAINPOOLP256T1_SUPPORT
   #define X509_BRAINPOOLP256T1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP256T1_SUPPORT != ENABLED && X509_BRAINPOOLP256T1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP256T1_SUPPORT parameter is not valid
#endif

//brainpoolP320r1 elliptic curve support
#ifndef X509_BRAINPOOLP320R1_SUPPORT
   #define X509_BRAINPOOLP320R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP320R1_SUPPORT != ENABLED && X509_BRAINPOOLP320R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP320R1_SUPPORT parameter is not valid
#endif
//brainpoolP320t1 elliptic curve support
#ifndef X509_BRAINPOOLP320T1_SUPPORT
   #define X509_BRAINPOOLP320T1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP320T1_SUPPORT != ENABLED && X509_BRAINPOOLP320T1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP320T1_SUPPORT parameter is not valid
#endif

//brainpoolP384r1 elliptic curve support
#ifndef X509_BRAINPOOLP384R1_SUPPORT
   #define X509_BRAINPOOLP384R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP384R1_SUPPORT != ENABLED && X509_BRAINPOOLP384R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP384R1_SUPPORT parameter is not valid
#endif

//brainpoolP384t1 elliptic curve support
#ifndef X509_BRAINPOOLP384T1_SUPPORT
   #define X509_BRAINPOOLP384T1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP384T1_SUPPORT != ENABLED && X509_BRAINPOOLP384T1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP384T1_SUPPORT parameter is not valid
#endif

//brainpoolP512r1 elliptic curve support
#ifndef X509_BRAINPOOLP512R1_SUPPORT
   #define X509_BRAINPOOLP512R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP512R1_SUPPORT != ENABLED && X509_BRAINPOOLP512R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP512R1_SUPPORT parameter is not valid
#endif

//brainpoolP512t1 elliptic curve support
#ifndef X509_BRAINPOOLP512T1_SUPPORT
   #define X509_BRAINPOOLP512T1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP512T1_SUPPORT != ENABLED && X509_BRAINPOOLP512T1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP512T1_SUPPORT parameter is not valid
#endif

//FRP256v1 elliptic curve support
#ifndef X509_FRP256V1_SUPPORT
   #define X509_FRP256V1_SUPPORT DISABLED
#elif (X509_FRP256V1_SUPPORT != ENABLED && X509_FRP256V1_SUPPORT != DISABLED)
   #error X509_FRP256V1_SUPPORT parameter is not valid
#endif

//SM2 elliptic curve support
#ifndef X509_SM2_SUPPORT
   #define X509_SM2_SUPPORT DISABLED
#elif (X509_SM2_SUPPORT != ENABLED && X509_SM2_SUPPORT != DISABLED)
   #error X509_SM2_SUPPORT parameter is not valid
#endif

//Ed25519 elliptic curve support
#ifndef X509_ED25519_SUPPORT
   #define X509_ED25519_SUPPORT DISABLED
#elif (X509_ED25519_SUPPORT != ENABLED && X509_ED25519_SUPPORT != DISABLED)
   #error X509_ED25519_SUPPORT parameter is not valid
#endif

//Ed448 elliptic curve support
#ifndef X509_ED448_SUPPORT
   #define X509_ED448_SUPPORT DISABLED
#elif (X509_ED448_SUPPORT != ENABLED && X509_ED448_SUPPORT != DISABLED)
   #error X509_ED448_SUPPORT parameter is not valid
#endif

//Minimum acceptable size for RSA modulus
#ifndef X509_MIN_RSA_MODULUS_SIZE
   #define X509_MIN_RSA_MODULUS_SIZE 1024
#elif (X509_MIN_RSA_MODULUS_SIZE < 512)
   #error X509_MIN_RSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for RSA modulus
#ifndef X509_MAX_RSA_MODULUS_SIZE
   #define X509_MAX_RSA_MODULUS_SIZE 4096
#elif (X509_MAX_RSA_MODULUS_SIZE < X509_MIN_RSA_MODULUS_SIZE)
   #error X509_MAX_RSA_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for DSA prime modulus
#ifndef X509_MIN_DSA_MODULUS_SIZE
   #define X509_MIN_DSA_MODULUS_SIZE 1024
#elif (X509_MIN_DSA_MODULUS_SIZE < 512)
   #error X509_MIN_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for DSA prime modulus
#ifndef X509_MAX_DSA_MODULUS_SIZE
   #define X509_MAX_DSA_MODULUS_SIZE 4096
#elif (X509_MAX_DSA_MODULUS_SIZE < X509_MIN_DSA_MODULUS_SIZE)
   #error X509_MAX_DSA_MODULUS_SIZE parameter is not valid
#endif

//Default size of serial numbers
#ifndef X509_SERIAL_NUMBER_SIZE
   #define X509_SERIAL_NUMBER_SIZE 20
#elif (X509_SERIAL_NUMBER_SIZE < 1)
   #error X509_SERIAL_NUMBER_SIZE parameter is not valid
#endif

//Maximum number of domain components
#ifndef X509_MAX_DOMAIN_COMPONENTS
   #define X509_MAX_DOMAIN_COMPONENTS 4
#elif (X509_MAX_DOMAIN_COMPONENTS < 1)
   #error X509_MAX_DOMAIN_COMPONENTS parameter is not valid
#endif

//Maximum number of subject alternative names
#ifndef X509_MAX_SUBJECT_ALT_NAMES
   #define X509_MAX_SUBJECT_ALT_NAMES 4
#elif (X509_MAX_SUBJECT_ALT_NAMES < 1)
   #error X509_MAX_SUBJECT_ALT_NAMES parameter is not valid
#endif

//Maximum number of certificate issuers
#ifndef X509_MAX_CERT_ISSUERS
   #define X509_MAX_CERT_ISSUERS 4
#elif (X509_MAX_CERT_ISSUERS < 1)
   #error X509_MAX_CERT_ISSUERS parameter is not valid
#endif

//Maximum number of CRL issuers
#ifndef X509_MAX_CRL_ISSUERS
   #define X509_MAX_CRL_ISSUERS 2
#elif (X509_MAX_CRL_ISSUERS < 1)
   #error X509_MAX_CRL_ISSUERS parameter is not valid
#endif

//Maximum number of distribution points
#ifndef X509_MAX_DISTR_POINTS
   #define X509_MAX_DISTR_POINTS 2
#elif (X509_MAX_DISTR_POINTS < 1)
   #error X509_MAX_DISTR_POINTS parameter is not valid
#endif

//Maximum number of full names
#ifndef X509_MAX_FULL_NAMES
   #define X509_MAX_FULL_NAMES 2
#elif (X509_MAX_FULL_NAMES < 1)
   #error X509_MAX_FULL_NAMES parameter is not valid
#endif

//Maximum number of access descriptions
#ifndef X509_MAX_ACCESS_DESCRIPTIONS
   #define X509_MAX_ACCESS_DESCRIPTIONS 2
#elif (X509_MAX_ACCESS_DESCRIPTIONS < 1)
   #error X509_MAX_ACCESS_DESCRIPTIONS parameter is not valid
#endif

//Maximum number of custom extensions
#ifndef X509_MAX_CUSTOM_EXTENSIONS
   #define X509_MAX_CUSTOM_EXTENSIONS 2
#elif (X509_MAX_CUSTOM_EXTENSIONS < 1)
   #error X509_MAX_CUSTOM_EXTENSIONS parameter is not valid
#endif

//Application specific extensions
#ifndef X509_PRIVATE_EXTENSIONS
   #define X509_PRIVATE_EXTENSIONS
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief PKCS #1 versions
 **/

typedef enum
{
   PKCS1_VERSION_1 = 0
} Pkcs1Version;


/**
 * @brief PKCS #8 versions
 **/

typedef enum
{
   PKCS8_VERSION_1 = 0,
   PKCS8_VERSION_2 = 1
} Pkcs8Version;


/**
 * @brief X.509 versions
 **/

typedef enum
{
   X509_VERSION_1 = 0,
   X509_VERSION_2 = 1,
   X509_VERSION_3 = 2
} X509Version;


/**
 * @brief Key usage
 **/

typedef enum
{
   X509_KEY_USAGE_DIGITAL_SIGNATURE = 0x0001,
   X509_KEY_USAGE_NON_REPUDIATION   = 0x0002,
   X509_KEY_USAGE_KEY_ENCIPHERMENT  = 0x0004,
   X509_KEY_USAGE_DATA_ENCIPHERMENT = 0x0008,
   X509_KEY_USAGE_KEY_AGREEMENT     = 0x0010,
   X509_KEY_USAGE_KEY_CERT_SIGN     = 0x0020,
   X509_KEY_USAGE_CRL_SIGN          = 0x0040,
   X509_KEY_USAGE_ENCIPHER_ONLY     = 0x0080,
   X509_KEY_USAGE_DECIPHER_ONLY     = 0x0100
} X509KeyUsageBitmap;


/**
 * @brief Extended key usage
 **/

typedef enum
{
   X509_EXT_KEY_USAGE_SERVER_AUTH      = 0x00000001,
   X509_EXT_KEY_USAGE_CLIENT_AUTH      = 0x00000002,
   X509_EXT_KEY_USAGE_CODE_SIGNING     = 0x00000004,
   X509_EXT_KEY_USAGE_EMAIL_PROTECTION = 0x00000008,
   X509_EXT_KEY_USAGE_IPSEC_END_SYSTEM = 0x00000010,
   X509_EXT_KEY_USAGE_IPSEC_TUNNEL     = 0x00000020,
   X509_EXT_KEY_USAGE_IPSEC_USER       = 0x00000040,
   X509_EXT_KEY_USAGE_TIME_STAMPING    = 0x00000080,
   X509_EXT_KEY_USAGE_OCSP_SIGNING     = 0x00000100,
   X509_EXT_KEY_USAGE_IPSEC_IKE        = 0x00000200,
   X509_EXT_KEY_USAGE_SSH_CLIENT       = 0x00000400,
   X509_EXT_KEY_USAGE_SSH_SERVER       = 0x00000800,
   X509_EXT_KEY_USAGE_DOC_SIGNING      = 0x00001000,
   X509_EXT_KEY_USAGE_ANY              = 0x00001FFF
} X509ExtKeyUsageBitmap;


/**
 * @brief General name types
 **/

typedef enum
{
   X509_GENERAL_NAME_TYPE_OTHER         = 0,
   X509_GENERAL_NAME_TYPE_RFC822        = 1,
   X509_GENERAL_NAME_TYPE_DNS           = 2,
   X509_GENERAL_NAME_TYPE_X400_ADDRESS  = 3,
   X509_GENERAL_NAME_TYPE_DIRECTORY     = 4,
   X509_GENERAL_NAME_TYPE_EDI_PARTY     = 5,
   X509_GENERAL_NAME_TYPE_URI           = 6,
   X509_GENERAL_NAME_TYPE_IP_ADDRESS    = 7,
   X509_GENERAL_NAME_TYPE_REGISTERED_ID = 8
} X509GeneralNameType;


/**
 * @brief Netscape certificate types
 **/

typedef enum
{
   X509_NS_CERT_TYPE_SSL_CLIENT = 0x01,
   X509_NS_CERT_TYPE_SSL_SERVER = 0x02,
   X509_NS_CERT_TYPE_SSL_CA     = 0x20
} X509NsCertTypeBitmap;


/**
 * @brief Reason flags
 **/

typedef enum
{
   X509_REASON_FLAGS_UNUSED                 = 0x0001,
   X509_REASON_FLAGS_KEY_COMPROMISE         = 0x0002,
   X509_REASON_FLAGS_CA_COMPROMISE          = 0x0004,
   X509_REASON_FLAGS_AFFILIATION_CHANGED    = 0x0008,
   X509_REASON_FLAGS_SUPERSEDED             = 0x0010,
   X509_REASON_FLAGS_CESSATION_OF_OPERATION = 0x0020,
   X509_REASON_FLAGS_CERTIFICATE_HOLD       = 0x0040,
   X509_REASON_FLAGS_PRIVILEGE_WITHDRAWN    = 0x0080,
   X509_REASON_FLAGS_AA_COMPROMISE          = 0x0100
} X509ReasonFlags;


/**
 * @brief CRL reasons
 **/

typedef enum
{
   X509_CRL_REASON_UNSPECIFIED            = 0,
   X509_CRL_REASON_KEY_COMPROMISE         = 1,
   X509_CRL_REASON_CA_COMPROMISE          = 2,
   X509_CRL_REASON_AFFILIATION_CHANGED    = 3,
   X509_CRL_REASON_SUPERSEDED             = 4,
   X509_CRL_REASON_CESSATION_OF_OPERATION = 5,
   X509_CRL_REASON_CERTIFICATE_HOLD       = 6,
   X509_CRL_REMOVE_FROM_CRL               = 8,
   X509_CRL_REASON_PRIVILEGE_WITHDRAWN    = 9,
   X509_CRL_REASON_AA_COMPROMISE          = 10
} X509CrlReasons;


/**
 * @brief Public Key types
 **/

typedef enum
{
   X509_KEY_TYPE_UNKNOWN = 0,
   X509_KEY_TYPE_RSA     = 1,
   X509_KEY_TYPE_RSA_PSS = 2,
   X509_KEY_TYPE_DSA     = 3,
   X509_KEY_TYPE_EC      = 4,
   X509_KEY_TYPE_SM2     = 5,
   X509_KEY_TYPE_X25519  = 6,
   X509_KEY_TYPE_ED25519 = 7,
   X509_KEY_TYPE_X448    = 8,
   X509_KEY_TYPE_ED448   = 9
} X509KeyType;


/**
 * @brief Signature algorithms
 **/

typedef enum
{
   X509_SIGN_ALGO_NONE    = 0,
   X509_SIGN_ALGO_RSA     = 1,
   X509_SIGN_ALGO_RSA_PSS = 2,
   X509_SIGN_ALGO_DSA     = 3,
   X509_SIGN_ALGO_ECDSA   = 4,
   X509_SIGN_ALGO_SM2     = 5,
   X509_SIGN_ALGO_ED25519 = 6,
   X509_SIGN_ALGO_ED448   = 7
} X509SignatureAlgo;


/**
 * @brief Hash algorithms
 **/

typedef enum
{
   X509_HASH_ALGO_NONE     = 0,
   X509_HASH_ALGO_MD5      = 1,
   X509_HASH_ALGO_SHA1     = 2,
   X509_HASH_ALGO_SHA224   = 3,
   X509_HASH_ALGO_SHA256   = 4,
   X509_HASH_ALGO_SHA384   = 5,
   X509_HASH_ALGO_SHA512   = 6,
   X509_HASH_ALGO_SHA3_224 = 7,
   X509_HASH_ALGO_SHA3_256 = 8,
   X509_HASH_ALGO_SHA3_384 = 9,
   X509_HASH_ALGO_SHA3_512 = 10,
   X509_HASH_ALGO_SM3      = 11
} X509HashAlgo;


/**
 * @brief String
 **/

typedef struct
{
   const char_t *value;
   size_t length;
} X509String;


/**
 * @brief Octet string
 **/

typedef struct
{
   const uint8_t *value;
   size_t length;
} X509OctetString;


/**
 * @brief Serial number
 **/

typedef struct
{
   const uint8_t *value;
   size_t length;
} X509SerialNumber;


/**
 * @brief Issuer or subject name
 **/

typedef struct
{
   X509OctetString raw;
   X509String commonName;
   X509String surname;
   X509String serialNumber;
   X509String countryName;
   X509String localityName;
   X509String stateOrProvinceName;
   X509String organizationName;
   X509String organizationalUnitName;
   X509String title;
   X509String name;
   X509String givenName;
   X509String initials;
   X509String generationQualifier;
   X509String dnQualifier;
   X509String pseudonym;
   X509String emailAddress;
   uint_t numDomainComponents;
   X509String domainComponents[X509_MAX_DOMAIN_COMPONENTS];
} X509Name;


/**
 * @brief Name attribute
 **/

typedef struct
{
   X509OctetString oid;
   uint_t type;
   X509String data;
} X509NameAttribute;


/**
 * @brief Validity
 **/

typedef struct
{
   DateTime notBefore;
   DateTime notAfter;
} X509Validity;


/**
 * @brief Algorithm identifier
 **/

typedef struct
{
   X509OctetString oid;
   X509OctetString params;
} X509AlgoId;


/**
 * @brief RSA public key
 **/

typedef struct
{
   X509OctetString n;
   X509OctetString e;
} X509RsaPublicKey;


/**
 * @brief DSA domain parameters
 **/

typedef struct
{
   X509OctetString p;
   X509OctetString q;
   X509OctetString g;
} X509DsaParameters;


/**
 * @brief DSA public key
 **/

typedef struct
{
   X509OctetString y;
} X509DsaPublicKey;


/**
 * @brief EC parameters
 **/

typedef struct
{
   X509OctetString namedCurve;
} X509EcParameters;


/**
 * @brief EC public key
 **/

typedef struct
{
   X509OctetString q;
} X509EcPublicKey;


/**
 * @brief Subject Public Key Information extension
 **/

typedef struct
{
   X509OctetString raw;
   X509OctetString oid;
   X509OctetString rawSubjectPublicKey;
#if (RSA_SUPPORT == ENABLED)
   X509RsaPublicKey rsaPublicKey;
#endif
#if (DSA_SUPPORT == ENABLED)
   X509DsaParameters dsaParams;
   X509DsaPublicKey dsaPublicKey;
#endif
#if (EC_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   X509EcParameters ecParams;
   X509EcPublicKey ecPublicKey;
#endif
} X509SubjectPublicKeyInfo;


/**
 * @brief Basic Constraints extension
 **/

typedef struct
{
   bool_t critical;
   bool_t cA;
   int_t pathLenConstraint;
} X509BasicConstraints;


/**
 * @brief Name Constraints extension
 **/

typedef struct
{
   bool_t critical;
   X509OctetString permittedSubtrees;
   X509OctetString excludedSubtrees;
} X509NameConstraints;


/**
 * @brief Key Usage extension
 **/

typedef struct
{
   bool_t critical;
   uint16_t bitmap;
} X509KeyUsage;


/**
 * @brief Extended Key Usage extension
 **/

typedef struct
{
   bool_t critical;
   uint16_t bitmap;
} X509ExtendedKeyUsage;


/**
 * @brief General name
 **/

typedef struct
{
   X509GeneralNameType type;
   const char_t *value;
   size_t length;
} X509GeneralName;


/**
 * @brief Subject Alternative Name extension
 **/

typedef struct
{
   bool_t critical;
   X509OctetString raw;
   uint_t numGeneralNames;
   X509GeneralName generalNames[X509_MAX_SUBJECT_ALT_NAMES];
} X509SubjectAltName;


/**
 * @brief Subject Key Identifier extension
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *value;
   size_t length;
} X509SubjectKeyId;


/**
 * @brief Authority Key Identifier extension
 **/

typedef struct
{
   bool_t critical;
   X509OctetString keyId;
} X509AuthKeyId;


/**
 * @brief Distribution Point Name structure
 **/

typedef struct
{
   uint_t numFullNames;
   X509GeneralName fullNames[X509_MAX_FULL_NAMES];
   X509NameAttribute relativeName;
} X509DistrPointName;


/**
 * @brief Distribution Point structure
 **/

typedef struct
{
   X509DistrPointName distrPointName;
   uint16_t reasonFlags;
   uint_t numCrlIssuers;
   X509GeneralName crlIssuers[X509_MAX_CRL_ISSUERS];
} X509DistrPoint;


/**
 * @brief CRL Distribution Points extension
 **/

typedef struct
{
   bool_t critical;
   X509OctetString raw;
   uint_t numDistrPoints;
   X509DistrPoint distrPoints[X509_MAX_DISTR_POINTS];
} X509CrlDistrPoints;


/**
 * @brief Access Description extension
 **/

typedef struct
{
   X509OctetString accessMethod;
   X509GeneralName accessLocation;
} X509AccessDescription;


/**
 * @brief Authority Information Access extension
 **/

typedef struct
{
   bool_t critical;
   X509OctetString raw;
   uint_t numAccessDescriptions;
   X509AccessDescription accessDescriptions[X509_MAX_ACCESS_DESCRIPTIONS];
} X509AuthInfoAccess;


/**
 * @brief PKIX OCSP No Check extension
 **/

typedef struct
{
   bool_t critical;
   bool_t present;
} X509PkixOcspNoCheck;


/**
 * @brief Netscape certificate type
 **/

typedef struct
{
   bool_t critical;
   uint8_t bitmap;
} X509NsCertType;


/**
 * @brief X.509 certificate extension
 **/

typedef struct
{
   X509OctetString oid;
   bool_t critical;
   X509OctetString data;
} X509Extension;


/**
 * @brief X.509 certificate extensions
 **/

typedef struct
{
   X509OctetString raw;
   X509BasicConstraints basicConstraints;
   X509NameConstraints nameConstraints;
   X509KeyUsage keyUsage;
   X509ExtendedKeyUsage extKeyUsage;
   X509SubjectAltName subjectAltName;
   X509SubjectKeyId subjectKeyId;
   X509AuthKeyId authKeyId;
   X509CrlDistrPoints crlDistrPoints;
   X509AuthInfoAccess authInfoAccess;
   X509PkixOcspNoCheck pkixOcspNoCheck;
   X509NsCertType nsCertType;
   uint_t numCustomExtensions;
   X509Extension customExtensions[X509_MAX_CUSTOM_EXTENSIONS];
   X509_PRIVATE_EXTENSIONS
} X509Extensions;


/**
 * @brief RSASSA-PSS parameters
 **/

typedef struct
{
   X509OctetString hashAlgo;
   X509OctetString maskGenAlgo;
   X509OctetString maskGenHashAlgo;
   size_t saltLen;
} X509RsaPssParameters;


/**
 * @brief Signature algorithm identifier
 **/

typedef struct
{
   X509OctetString oid;
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   X509RsaPssParameters rsaPssParams;
#endif
} X509SignAlgoId;


/**
 * @brief TBSCertificate structure
 **/

typedef struct
{
   X509OctetString raw;
   X509Version version;
   X509SerialNumber serialNumber;
   X509SignAlgoId signatureAlgo;
   X509Name issuer;
   X509Validity validity;
   X509Name subject;
   X509SubjectPublicKeyInfo subjectPublicKeyInfo;
   X509Extensions extensions;
} X509TbsCertificate;


/**
 * @brief X.509 certificate
 **/

typedef struct
{
   X509OctetString raw;
   X509TbsCertificate tbsCert;
   X509SignAlgoId signatureAlgo;
   X509OctetString signatureValue;
} X509CertInfo;


/**
 * @brief CRL Reason extension
 **/

typedef struct
{
   bool_t critical;
   uint8_t value;
} X509CrlReason;


/**
 * @brief Invalidity Date extension
 **/

typedef struct
{
   bool_t critical;
   DateTime value;
} X509InvalidityDate;


/**
 * @brief Certificate Issuer extension
 **/

typedef struct
{
   bool_t critical;
   X509OctetString raw;
   uint_t numGeneralNames;
   X509GeneralName generalNames[X509_MAX_CERT_ISSUERS];
} X509CertificateIssuer;


/**
 * @brief CRL entry extensions
 **/

typedef struct
{
   X509OctetString raw;
   X509CrlReason reasonCode;
   X509InvalidityDate invalidityDate;
   X509CertificateIssuer certIssuer;
} X509CrlEntryExtensions;


/**
 * @brief Revoked certificate
 **/

typedef struct
{
   X509SerialNumber userCert;
   DateTime revocationDate;
   X509CrlEntryExtensions crlEntryExtensions;
} X509RevokedCertificate;


/**
 * @brief CRL number
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *value;
   size_t length;
} X509CrlNumber;


/**
 * @brief Delta CRL Indicator extension
 **/

typedef struct
{
   bool_t critical;
   X509OctetString baseCrlNumber;
} X509DeltaCrlIndicator;


/**
 * @brief Issuing Distribution Point extension
 **/

typedef struct
{
   bool_t critical;
   X509DistrPointName distributionPoint;
   bool_t onlyContainsUserCerts;
   bool_t onlyContainsCaCerts;
   uint16_t onlySomeReasons;
   bool_t indirectCrl;
   bool_t onlyContainsAttributeCerts;
} X509IssuingDistrPoint;


/**
 * @brief CRL extensions
 **/

typedef struct
{
   X509OctetString raw;
   X509CrlNumber crlNumber;
   X509DeltaCrlIndicator deltaCrlIndicator;
   X509IssuingDistrPoint issuingDistrPoint;
   X509AuthKeyId authKeyId;
} X509CrlExtensions;


/**
 * @brief TBSCertList structure
 **/

typedef struct
{
   X509OctetString raw;
   X509Version version;
   X509SignAlgoId signatureAlgo;
   X509Name issuer;
   DateTime thisUpdate;
   DateTime nextUpdate;
   X509OctetString revokedCerts;
   X509CrlExtensions crlExtensions;
} X509TbsCertList;


/**
 * @brief CRL (Certificate Revocation List)
 **/

typedef struct
{
   X509TbsCertList tbsCertList;
   X509SignAlgoId signatureAlgo;
   X509OctetString signatureValue;
} X509CrlInfo;


/**
 * @brief PKCS #9 ChallengePassword attribute
 **/

typedef struct
{
   const char_t *value;
   size_t length;
} X509ChallengePassword;


/**
 * @brief CSR attribute
 **/

typedef struct
{
   X509OctetString oid;
   X509OctetString data;
} X509Attribute;


/**
 * @brief CSR attributes
 **/

typedef struct
{
   X509OctetString raw;
   X509ChallengePassword challengePwd;
   X509Extensions extensionReq;
} X509Attributes;


/**
 * @brief CertificationRequestInfo structure
 **/

typedef struct
{
   X509OctetString raw;
   X509Version version;
   X509Name subject;
   X509SubjectPublicKeyInfo subjectPublicKeyInfo;
   X509Attributes attributes;
} X509CertRequestInfo;


/**
 * @brief CSR (Certificate Signing Request)
 **/

typedef struct
{
   X509CertRequestInfo certReqInfo;
   X509SignAlgoId signatureAlgo;
   X509OctetString signatureValue;
} X509CsrInfo;


/**
 * @brief Certificate parsing options
 **/

typedef struct
{
   bool_t ignoreUnknownExtensions; ///<Ignore unknown extensions
} X509Options;


//X.509 related constants
extern const uint8_t X509_COMMON_NAME_OID[3];
extern const uint8_t X509_SURNAME_OID[3];
extern const uint8_t X509_SERIAL_NUMBER_OID[3];
extern const uint8_t X509_COUNTRY_NAME_OID[3];
extern const uint8_t X509_LOCALITY_NAME_OID[3];
extern const uint8_t X509_STATE_OR_PROVINCE_NAME_OID[3];
extern const uint8_t X509_ORGANIZATION_NAME_OID[3];
extern const uint8_t X509_ORGANIZATIONAL_UNIT_NAME_OID[3];
extern const uint8_t X509_TITLE_OID[3];
extern const uint8_t X509_NAME_OID[3];
extern const uint8_t X509_GIVEN_NAME_OID[3];
extern const uint8_t X509_INITIALS_OID[3];
extern const uint8_t X509_GENERATION_QUALIFIER_OID[3];
extern const uint8_t X509_DN_QUALIFIER_OID[3];
extern const uint8_t X509_PSEUDONYM_OID[3];
extern const uint8_t X509_DOMAIN_COMPONENT_OID[10];

extern const uint8_t X509_SUBJECT_DIR_ATTR_OID[3];
extern const uint8_t X509_SUBJECT_KEY_ID_OID[3];
extern const uint8_t X509_KEY_USAGE_OID[3];
extern const uint8_t X509_SUBJECT_ALT_NAME_OID[3];
extern const uint8_t X509_ISSUER_ALT_NAME_OID[3];
extern const uint8_t X509_BASIC_CONSTRAINTS_OID[3];
extern const uint8_t X509_CRL_NUMBER_OID[3];
extern const uint8_t X509_REASON_CODE_OID[3];
extern const uint8_t X509_INVALIDITY_DATE_OID[3];
extern const uint8_t X509_DELTA_CRL_INDICATOR_OID[3];
extern const uint8_t X509_ISSUING_DISTR_POINT_OID[3];
extern const uint8_t X509_CERTIFICATE_ISSUER_OID[3];
extern const uint8_t X509_NAME_CONSTRAINTS_OID[3];
extern const uint8_t X509_CRL_DISTR_POINTS_OID[3];
extern const uint8_t X509_CERTIFICATE_POLICIES_OID[3];
extern const uint8_t X509_POLICY_MAPPINGS_OID[3];
extern const uint8_t X509_AUTHORITY_KEY_ID_OID[3];
extern const uint8_t X509_POLICY_CONSTRAINTS_OID[3];
extern const uint8_t X509_EXTENDED_KEY_USAGE_OID[3];
extern const uint8_t X509_FRESHEST_CRL_OID[3];
extern const uint8_t X509_INHIBIT_ANY_POLICY_OID[3];
extern const uint8_t X509_AUTH_INFO_ACCESS_OID[8];
extern const uint8_t X509_PKIX_OCSP_NO_CHECK_OID[9];
extern const uint8_t X509_NS_CERT_TYPE_OID[9];

extern const uint8_t X509_ANY_EXT_KEY_USAGE_OID[4];
extern const uint8_t X509_KP_SERVER_AUTH_OID[8];
extern const uint8_t X509_KP_CLIENT_AUTH_OID[8];
extern const uint8_t X509_KP_CODE_SIGNING_OID[8];
extern const uint8_t X509_KP_EMAIL_PROTECTION_OID[8];
extern const uint8_t X509_KP_IPSEC_END_SYSTEM_OID[8];
extern const uint8_t X509_KP_IPSEC_TUNNEL_OID[8];
extern const uint8_t X509_KP_IPSEC_USER_OID[8];
extern const uint8_t X509_KP_TIME_STAMPING_OID[8];
extern const uint8_t X509_KP_OCSP_SIGNING_OID[8];
extern const uint8_t X509_KP_IPSEC_IKE_OID[8];
extern const uint8_t X509_KP_SSH_CLIENT_OID[8];
extern const uint8_t X509_KP_SSH_SERVER_OID[8];
extern const uint8_t X509_KP_DOC_SIGNING_OID[8];

extern const uint8_t X509_AD_CA_ISSUERS[8];
extern const uint8_t X509_AD_OCSP[8];

extern const uint8_t PKCS9_EMAIL_ADDR_OID[9];
extern const uint8_t PKCS9_CHALLENGE_PASSWORD_OID[9];
extern const uint8_t PKCS9_EXTENSION_REQUEST_OID[9];

extern const X509Options X509_DEFAULT_OPTIONS;

//X.509 related functions
bool_t x509CompareName(const uint8_t *name1, size_t nameLen1,
   const uint8_t *name2, size_t nameLen2);

bool_t x509IsSignAlgoSupported(X509SignatureAlgo signAlgo);
bool_t x509IsHashAlgoSupported(X509HashAlgo hashAlgo);
bool_t x509IsCurveSupported(const uint8_t *oid, size_t length);

error_t x509GetSignHashAlgo(const X509SignAlgoId *signAlgoId,
   X509SignatureAlgo *signAlgo, const HashAlgo **hashAlgo);

X509KeyType x509GetPublicKeyType(const uint8_t *oid, size_t length);
const EcCurve *x509GetCurve(const uint8_t *oid, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
