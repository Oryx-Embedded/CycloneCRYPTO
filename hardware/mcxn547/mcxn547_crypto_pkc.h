/**
 * @file mcxn547_crypto_pkc.h
 * @brief NXP MCX N547 public-key hardware accelerator (PKA)
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
 * @version 2.5.4
 **/

#ifndef _MCXN547_CRYPTO_PKC_H
#define _MCXN547_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"
#include <mcuxClEcc.h>

//Public-key hardware accelerator
#ifndef MCXN547_CRYPTO_PKC_SUPPORT
   #define MCXN547_CRYPTO_PKC_SUPPORT DISABLED
#elif (MCXN547_CRYPTO_PKC_SUPPORT != ENABLED && MCXN547_CRYPTO_PKC_SUPPORT != DISABLED)
   #error MCXN547_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RSA primitive arguments
 **/

typedef struct
{
   uint8_t n[512];
   uint8_t e[512];
   uint8_t d[512];
   uint8_t p[512];
   uint8_t q[512];
   uint8_t dp[512];
   uint8_t dq[512];
   uint8_t qinv[512];
   uint8_t m[512];
   uint8_t c[512];
} ElsRsaArgs;


/**
 * @brief ELS ECC primitive arguments
 **/

typedef struct
{
   uint8_t p[66];
   uint8_t a[66];
   uint8_t b[66];
   uint8_t g[132];
   uint8_t q[66];
   uint8_t d[66];
   uint8_t input[132];
   uint8_t output[132];
} ElsEccArgs;


/**
 * @brief ELS ECDSA primitive arguments
 **/

typedef struct
{
   uint8_t p[66];
   uint8_t a[66];
   uint8_t b[66];
   uint8_t g[132];
   uint8_t q[66];
   uint8_t privateKey[66];
   uint8_t publicKey[132];
   uint8_t signature[132];
   uint8_t r[66];
} ElsEcdsaArgs;


/**
 * @brief ELS MontDH primitive arguments
 **/

typedef struct
{
   uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
   uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
   uint8_t sharedSecret[MCUXCLECC_MONTDH_CURVE448_SIZE_SHAREDSECRET];
} ElsMontDhArgs;


/**
 * @brief ELS EdDSA primitive arguments
 **/

typedef struct
{
   uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
   uint8_t privKeyData[MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEYDATA];
   uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
   uint8_t pubKeyData[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY];
   uint32_t keyPairDesc[MCUXCLECC_EDDSA_GENERATEKEYPAIR_DESCRIPTOR_SIZE_IN_WORDS];
   uint32_t protocolDesc[MCUXCLECC_EDDSA_ED25519_SIGNATURE_PROTOCOL_DESCRIPTOR_SIZE_IN_WORD(256)];
   uint8_t signature[MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE];
} ElsEddsaArgs;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
