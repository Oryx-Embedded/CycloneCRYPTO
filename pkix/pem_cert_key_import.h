/**
 * @file pem_cert_key_import.h
 * @brief PEM certificate public key import functions
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
 * @version 2.5.0
 **/

#ifndef _PEM_CERT_KEY_IMPORT_H
#define _PEM_CERT_KEY_IMPORT_H

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
error_t pemImportRsaCertPublicKey(RsaPublicKey *publicKey, const char_t *input,
   size_t length);

error_t pemImportDsaCertPublicKey(DsaPublicKey *publicKey, const char_t *input,
   size_t length);

error_t pemImportEcCertPublicKey(EcPublicKey *publicKey, const char_t *input,
   size_t length);

error_t pemImportEddsaCertPublicKey(EddsaPublicKey *publicKey,
   const char_t *input, size_t length);

X509KeyType pemGetCertPublicKeyType(const char_t *input, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
