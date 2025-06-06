/**
 * @file pem_key_import.h
 * @brief PEM key file import functions
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

#ifndef _PEM_KEY_IMPORT_H
#define _PEM_KEY_IMPORT_H

//Dependencies
#include "core/crypto.h"
#include "pkix/pem_common.h"
#include "pkix/x509_common.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PEM related functions
error_t pemImportRsaPublicKey(RsaPublicKey *publicKey, const char_t *input,
   size_t length);

error_t pemImportRsaPrivateKey(RsaPrivateKey *privateKey, const char_t *input,
   size_t length, const char_t *password);

error_t pemImportDsaPublicKey(DsaPublicKey *publicKey, const char_t *input,
   size_t length);

error_t pemImportDsaPrivateKey(DsaPrivateKey *privateKey, const char_t *input,
   size_t length, const char_t *password);

error_t pemImportEcPublicKey(EcPublicKey *publicKey, const char_t *input,
   size_t length);

error_t pemImportEcPrivateKey(EcPrivateKey *privateKey, const char_t *input,
   size_t length, const char_t *password);

error_t pemImportEddsaPublicKey(EddsaPublicKey *publicKey, const char_t *input,
   size_t length);

error_t pemImportEddsaPrivateKey(EddsaPrivateKey *privateKey,
   const char_t *input, size_t length, const char_t *password);

X509KeyType pemGetPublicKeyType(const char_t *input, size_t length);
const EcCurve *pemGetPublicKeyCurve(const char_t *input, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
