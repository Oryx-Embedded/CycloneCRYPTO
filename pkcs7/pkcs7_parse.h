/**
 * @file pkcs7_parse.h
 * @brief PKCS #7 message parsing
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

#ifndef _PKCS7_PARSE_H
#define _PKCS7_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "pkcs7/pkcs7_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKCS #7 related functions
error_t pkcs7ParseContentInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7ContentInfo *contentInfo);

error_t pkcs7ParseSignedData(const uint8_t *data, size_t length,
   Pkcs7SignedData *signedData);

error_t pkcs7ParseEnvelopedData(const uint8_t *data, size_t length,
   Pkcs7EnvelopedData *envelopedData);

error_t pkcs7ParseDigestAlgos(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7DigestAlgos *digestAlgos);

error_t pkcs7ParseCertificates(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7Certificates *certificates);

error_t pkcs7ParseCrls(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7Crls *crls);

error_t pkcs7ParseSignerInfos(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7SignerInfos *signerInfos);

error_t pkcs7ParseSignerInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7SignerInfo *signerInfo);

error_t pkcs7ParseIssuerAndSerialNumber(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7IssuerAndSerialNumber *issuerAndSerialNumber);

error_t pkcs7ParseAuthenticatedAttributes(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7AuthenticatedAttributes *authenticatedAttributes);

error_t pkcs7ParseDigestEncryptionAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignAlgoId *digestEncryptionAlgo);

error_t pkcs7ParseEncryptedDigest(const uint8_t *data, size_t length,
   size_t *totalLength, X509OctetString *encryptedDigest);

error_t pkcs7ParseUnauthenticatedAttributes(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7UnauthenticatedAttributes *unauthenticatedAttributes);

error_t pkcs7ParseAttribute(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7Attribute *attribute);

error_t pkcs7FindAttribute(const uint8_t *data, size_t length,
   const uint8_t *oid, size_t oidLen, Pkcs7Attribute *attribute);

error_t pkcs7ParseRecipientInfos(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7RecipientInfos *recipientInfos);

error_t pkcs7ParseRecipientInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7RecipientInfo *recipientInfo);

error_t pkcs7ParseEncryptedKey(const uint8_t *data, size_t length,
   size_t *totalLength, X509OctetString *encryptedKey);

error_t pkcs7ParseEncryptedContentInfo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7EncryptedContentInfo *encryptedContentInfo);

error_t pkcs7ParseContentEncrAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs7ContentEncrAlgo *contentEncrAlgo);

error_t pkcs7ParseAlgoId(const uint8_t *data, size_t length,
   size_t *totalLength, X509AlgoId *algoId);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
