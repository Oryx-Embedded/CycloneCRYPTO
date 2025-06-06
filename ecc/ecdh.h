/**
 * @file ecdh.h
 * @brief ECDH (Elliptic Curve Diffie-Hellman) key exchange
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

#ifndef _ECDH_H
#define _ECDH_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"
#include "ecc/ec_curves.h"

//X25519 supported?
#if (X25519_SUPPORT == ENABLED)
   #include "ecc/x25519.h"
#endif

//X448 supported?
#if (X448_SUPPORT == ENABLED)
   #include "ecc/x448.h"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ECDH context
 **/

typedef struct
{
   const EcCurve *curve; ///<Elliptic curve parameters
   EcPrivateKey da;      ///<One's own EC key pair
   EcPublicKey qb;       ///<Peer's EC public key
} EcdhContext;


//ECDH related functions
void ecdhInit(EcdhContext *context);
void ecdhFree(EcdhContext *context);

error_t ecdhSetCurve(EcdhContext *context, const EcCurve *curve);

error_t ecdhGenerateKeyPair(EcdhContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t ecdhExportPublicKey(EcdhContext *context, uint8_t *output,
   size_t *written, EcPublicKeyFormat format);

error_t ecdhImportPeerPublicKey(EcdhContext *context, const uint8_t *input,
   size_t length, EcPublicKeyFormat format);

error_t ecdhCheckPublicKey(EcdhContext *context, const EcPublicKey *publicKey);

error_t ecdhComputeSharedSecret(EcdhContext *context, uint8_t *output,
   size_t outputSize, size_t *outputLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
