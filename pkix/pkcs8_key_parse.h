/**
 * @file pkcs8_key_parse.h
 * @brief PKCS #8 key parsing
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

#ifndef _PKCS8_KEY_PARSE_H
#define _PKCS8_KEY_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RSA private key
 **/

typedef struct
{
   int32_t version;
   X509OctetString n;
   X509OctetString e;
   X509OctetString d;
   X509OctetString p;
   X509OctetString q;
   X509OctetString dp;
   X509OctetString dq;
   X509OctetString qinv;
} Pkcs8RsaPrivateKey;


/**
 * @brief DSA private key
 **/

typedef struct
{
   X509OctetString x;
} Pkcs8DsaPrivateKey;


/**
 * @brief EC private key
 **/

typedef struct
{
   int32_t version;
   X509OctetString d;
} Pkcs8EcPrivateKey;


/**
 * @brief EdDSA private key
 **/

typedef struct
{
   X509OctetString d;
} Pkcs8EddsaPrivateKey;


/**
 * @brief EdDSA public key
 **/

typedef struct
{
   X509OctetString q;
} Pkcs8EddsaPublicKey;


/**
 * @brief Private key information
 **/

typedef struct
{
   int32_t version;
   X509OctetString oid;
#if (RSA_SUPPORT == ENABLED)
   Pkcs8RsaPrivateKey rsaPrivateKey;
#endif
#if (DSA_SUPPORT == ENABLED)
   X509DsaParameters dsaParams;
   Pkcs8DsaPrivateKey dsaPrivateKey;
   X509DsaPublicKey dsaPublicKey;
#endif
#if (EC_SUPPORT == ENABLED)
   X509EcParameters ecParams;
   Pkcs8EcPrivateKey ecPrivateKey;
   X509EcPublicKey ecPublicKey;
#endif
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   Pkcs8EddsaPrivateKey eddsaPrivateKey;
   Pkcs8EddsaPublicKey eddsaPublicKey;
#endif
} Pkcs8PrivateKeyInfo;


/**
 * @brief Encrypted private key information
 **/

typedef struct
{
   X509AlgoId encryptionAlgo;
   X509OctetString encryptedData;
} Pkcs8EncryptedPrivateKeyInfo;


//Key parsing functions
error_t pkcs8ParsePrivateKeyInfo(const uint8_t *data, size_t length,
   Pkcs8PrivateKeyInfo *privateKeyInfo);

error_t pkcs8ParsePrivateKeyAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs8PrivateKeyInfo *privateKeyInfo);

error_t pkcs8ParseRsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8RsaPrivateKey *rsaPrivateKey);

error_t pkcs8ParseDsaPrivateKey(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams, Pkcs8DsaPrivateKey *dsaPrivateKey,
   X509DsaPublicKey *dsaPublicKey);

error_t pkcs8ParseEcPrivateKey(const uint8_t *data, size_t length,
   X509EcParameters *ecParams, Pkcs8EcPrivateKey *ecPrivateKey,
   X509EcPublicKey *ecPublicKey);

error_t pkcs8ParseEcPublicKey(const uint8_t *data, size_t length,
   X509EcPublicKey *ecPublicKey);

error_t pkcs8ParseEddsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8EddsaPrivateKey *eddsaPrivateKey);

error_t pkcs8ParseEddsaPublicKey(const uint8_t *data, size_t length,
   Pkcs8EddsaPublicKey *eddsaPublicKey);

error_t pkcs8ParseEncryptedPrivateKeyInfo(const uint8_t *data, size_t length,
   Pkcs8EncryptedPrivateKeyInfo *encryptedPrivateKeyInfo);

error_t pkcs8ParseEncryptionAlgoId(const uint8_t *data, size_t length,
   size_t *totalLength, X509AlgoId *encryptionAlgoId);

error_t pkcs8ImportRsaPrivateKey(RsaPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo);

error_t pkcs8ImportDsaPrivateKey(DsaPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo);

error_t pkcs8ImportEcPrivateKey(EcPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo);

error_t pkcs8ImportEddsaPrivateKey(EddsaPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
