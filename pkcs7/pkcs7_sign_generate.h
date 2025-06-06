/**
 * @file pkcs7_sign_generate.h
 * @brief PKCS #7 signature generation
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

#ifndef _PKCS7_SIGN_GENERATE_H
#define _PKCS7_SIGN_GENERATE_H

//Dependencies
#include "core/crypto.h"
#include "pkcs7/pkcs7_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKCS #7 related functions
error_t pkcs7GenerateSignedData(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *content, size_t contentLen, const X509CertInfo *signerCertInfo,
   const Pkcs7AuthenticatedAttributes *authenticatedAttributes,
   const Pkcs7UnauthenticatedAttributes *unauthenticatedAttributes,
   const X509SignAlgoId *signatureAlgo, const void *signerPrivateKey,
   uint8_t *output, size_t *written);

error_t pkcs7GenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *digest, const Pkcs7SignerInfo *signerInfo,
   const void *privateKey, uint8_t *output, size_t *written);

error_t pkcs7GenerateRsaSignature(const uint8_t *digest,
   const Pkcs7SignerInfo *signerInfo, const RsaPrivateKey *privateKey,
   uint8_t *output, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
