/**
 * @file x509_key_parse.h
 * @brief Parsing of ASN.1 encoded keys
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

#ifndef _X509_KEY_PARSE_H
#define _X509_KEY_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Key parsing functions
error_t x509ParseSubjectPublicKeyInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *subjectPublicKeyInfo);

error_t x509ParseAlgoId(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *subjectPublicKeyInfo);

error_t x509ParseRsaPublicKey(const uint8_t *data, size_t length,
   X509RsaPublicKey *rsaPublicKey);

error_t x509ParseDsaPublicKey(const uint8_t *data, size_t length,
   X509DsaPublicKey *dsaPublicKey);

error_t x509ParseDsaParameters(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams);

error_t x509ParseEcPublicKey(const uint8_t *data, size_t length,
   X509EcPublicKey *ecPublicKey);

error_t x509ParseEcParameters(const uint8_t *data, size_t length,
   X509EcParameters *ecParams);

error_t x509ImportRsaPublicKey(RsaPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo);

error_t x509ImportDsaPublicKey(DsaPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo);

error_t x509ImportEcPublicKey(EcPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo);

error_t x509ImportEddsaPublicKey(EddsaPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
