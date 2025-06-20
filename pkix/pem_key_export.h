/**
 * @file pem_key_export.h
 * @brief PEM key file export functions
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

#ifndef _PEM_KEY_EXPORT_H
#define _PEM_KEY_EXPORT_H

//Dependencies
#include "core/crypto.h"
#include "pkix/pem_common.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief PEM public key formats
 **/

typedef enum
{
   PEM_PUBLIC_KEY_FORMAT_DEFAULT = 0, ///<Default format
   PEM_PUBLIC_KEY_FORMAT_PKCS1   = 1, ///<PKCS #1 format
   PEM_PUBLIC_KEY_FORMAT_RFC7468 = 2  ///<RFC 7468 format
} PemPublicKeyFormat;


/**
 * @brief PEM private key formats
 **/

typedef enum
{
   PEM_PRIVATE_KEY_FORMAT_DEFAULT  = 0, ///<Default format
   PEM_PRIVATE_KEY_FORMAT_PKCS1    = 1, ///<PKCS #1 format
   PEM_PRIVATE_KEY_FORMAT_PKCS8    = 2, ///<PKCS #8 v1 format
   PEM_PRIVATE_KEY_FORMAT_PKCS8_V2 = 3, ///<PKCS #8 v2 format
   PEM_PRIVATE_KEY_FORMAT_RFC5915  = 4  ///<RFC 5915 format
} PemPrivateKeyFormat;


//PEM related functions
error_t pemExportRsaPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format);

error_t pemExportRsaPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format);

error_t pemExportRsaPssPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format);

error_t pemExportRsaPssPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format);

error_t pemExportDsaPublicKey(const DsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format);

error_t pemExportDsaPrivateKey(const DsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format);

error_t pemExportEcPublicKey(const EcPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format);

error_t pemExportEcPrivateKey(const EcPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format);

error_t pemExportEddsaPublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format);

error_t pemExportEddsaPrivateKey(const EddsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
