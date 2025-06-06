/**
 * @file x509_sign_verify.h
 * @brief RSA/DSA/ECDSA/EdDSA signature verification
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

#ifndef _X509_SIGN_VERIFY_H
#define _X509_SIGN_VERIFY_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Signature verification callback function
 **/

typedef error_t (*X509SignVerifyCallback)(const X509OctetString *tbsData,
   const X509SignAlgoId *signAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);


//X.509 related functions
error_t x509RegisterSignVerifyCallback(X509SignVerifyCallback callback);

error_t x509VerifySignature(const X509OctetString *tbsData,
   const X509SignAlgoId *signAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

error_t x509VerifyRsaSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

error_t x509VerifyRsaPssSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, size_t saltLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

error_t x509VerifyDsaSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

error_t x509VerifyEcdsaSignature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

error_t x509VerifySm2Signature(const X509OctetString *tbsData,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

error_t x509VerifyEd25519Signature(const X509OctetString *tbsData,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

error_t x509VerifyEd448Signature(const X509OctetString *tbsData,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
