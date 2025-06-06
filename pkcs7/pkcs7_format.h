/**
 * @file pkcs7_format.h
 * @brief PKCS #7 message formatting
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

#ifndef _PKCS7_FORMAT_H
#define _PKCS7_FORMAT_H

//Dependencies
#include "core/crypto.h"
#include "pkcs7/pkcs7_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKCS #7 related functions
error_t pkcs7FormatContentInfo(const Pkcs7ContentInfo *contentInfo,
   uint8_t *output, size_t *written);

error_t pkcs7FormatSignedData(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7SignedData *signedData, const void *signerPrivateKey,
   uint8_t *output, size_t *written);

error_t pkcs7FormatEnvelopedData(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertInfo *recipientCertInfo, const Pkcs7EnvelopedData *envelopedData,
   const uint8_t *plaintext, size_t plaintextLen, uint8_t *output, size_t *written);

error_t pkcs7FormatDigestAlgos(const Pkcs7DigestAlgos *digestAlgos,
   uint8_t *output, size_t *written);

error_t pkcs7FormatCertificates(const Pkcs7Certificates *certificates,
   uint8_t *output, size_t *written);

error_t pkcs7FormatCrls(const Pkcs7Crls *crls, uint8_t *output,
   size_t *written);

error_t pkcs7FormatSignerInfos(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7SignerInfos *signerInfos, const void *signerPrivateKey,
   uint8_t *output, size_t *written);

error_t pkcs7FormatSignerInfo(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7SignerInfo *signerInfo, const void *signerPrivateKey,
   uint8_t *output, size_t *written);

error_t pkcs7FormatIssuerAndSerialNumber(const Pkcs7IssuerAndSerialNumber *issuerAndSerialNumber,
   uint8_t *output, size_t *written);

error_t pkcs7FormatAuthenticatedAttributes(const Pkcs7AuthenticatedAttributes *authenticatedAttributes,
   uint8_t *output, size_t *written);

error_t pkcs7FormatDigestEncryptionAlgo(const X509SignAlgoId *digestEncryptionAlgo,
   uint8_t *output, size_t *written);

error_t pkcs7FormatEncryptedDigest(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *digest, const Pkcs7SignerInfo *signerInfo,
   const void *signerPrivateKey, uint8_t *output, size_t *written);

error_t pkcs7FormatUnauthenticatedAttributes(const Pkcs7UnauthenticatedAttributes *unauthenticatedAttributes,
   uint8_t *output, size_t *written);

error_t pkcs7FormatAttribute(const Pkcs7Attribute *attribute, uint8_t *output,
   size_t *written);

error_t pkcs7AddAttribute(const Pkcs7Attribute *attribute, uint8_t *attributes,
   size_t *length);

error_t pkcs7FormatRecipientInfos(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7RecipientInfos *recipientInfos, const X509CertInfo *recipientCertInfo,
   const uint8_t *key, size_t keyLen, uint8_t *output, size_t *written);

error_t pkcs7FormatRecipientInfo(const PrngAlgo *prngAlgo, void *prngContext,
   const Pkcs7RecipientInfo *recipientInfo, const X509CertInfo *recipientCertInfo,
   const uint8_t *key, size_t keyLen, uint8_t *output, size_t *written);

error_t pkcs7FormatEncryptedKey(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertInfo *recipientCertInfo, const uint8_t *key, size_t keyLen,
   uint8_t *output, size_t *written);

error_t pkcs7FormatEncryptedContentInfo(const Pkcs7EncryptedContentInfo *encryptedContentInfo,
   const uint8_t *key, size_t keyLen, const uint8_t *plaintext, size_t plaintextLen,
   uint8_t *output, size_t *written);

error_t pkcs7FormatContentEncrAlgo(const Pkcs7ContentEncrAlgo *contentEncrAlgo,
   uint8_t *output, size_t *written);

error_t pkcs7FormatAlgoId(const X509AlgoId *algoId, uint8_t *output,
   size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
