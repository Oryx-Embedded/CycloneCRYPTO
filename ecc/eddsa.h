/**
 * @file eddsa.h
 * @brief EdDSA (Edwards-Curve Digital Signature Algorithm)
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

#ifndef _EDDSA_H
#define _EDDSA_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"
#include "ecc/ec_curves.h"

//Maximum size of EdDSA public keys
#if (ED448_SUPPORT == ENABLED)
   #define EDDSA_MAX_PUBLIC_KEY_LEN 57
#else
   #define EDDSA_MAX_PUBLIC_KEY_LEN 32
#endif

//Maximum size of EdDSA private keys
#if (ED448_SUPPORT == ENABLED)
   #define EDDSA_MAX_PRIVATE_KEY_LEN 57
#else
   #define EDDSA_MAX_PRIVATE_KEY_LEN 32
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EdDSA public key
 **/

typedef struct
{
   const EcCurve *curve;                ///<Elliptic curve parameters
   uint8_t q[EDDSA_MAX_PUBLIC_KEY_LEN]; ///<Public key
} EddsaPublicKey;


/**
 * @brief EdDSA private key
 **/

typedef struct
{
   const EcCurve *curve;                 ///<Elliptic curve parameters
   uint8_t d[EDDSA_MAX_PRIVATE_KEY_LEN]; ///<Private key
   int_t slot;                           ///<Private key slot
   EddsaPublicKey q;                     ///<Public key
} EddsaPrivateKey;


//EdDSA related functions
void eddsaInitPublicKey(EddsaPublicKey *key);
void eddsaFreePublicKey(EddsaPublicKey *key);

void eddsaInitPrivateKey(EddsaPrivateKey *key);
void eddsaFreePrivateKey(EddsaPrivateKey *key);

error_t eddsaGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EddsaPrivateKey *privateKey,
   EddsaPublicKey *publicKey);

error_t eddsaGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurve *curve, EddsaPrivateKey *privateKey);

error_t eddsaGeneratePublicKey(const EddsaPrivateKey *privateKey,
   EddsaPublicKey *publicKey);

error_t eddsaImportPublicKey(EddsaPublicKey *key, const EcCurve *curve,
   const uint8_t *input, size_t length);

error_t eddsaExportPublicKey(const EddsaPublicKey *key, uint8_t *output,
   size_t *written);

error_t eddsaImportPrivateKey(EddsaPrivateKey *key, const EcCurve *curve,
   const uint8_t *data, size_t length);

error_t eddsaExportPrivateKey(const EddsaPrivateKey *key, uint8_t *output,
   size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

//Ed25519 supported?
#if (ED25519_SUPPORT == ENABLED)
   #include "ecc/ed25519.h"
#endif

//Ed448 supported?
#if (ED448_SUPPORT == ENABLED)
   #include "ecc/ed448.h"
#endif

#endif
