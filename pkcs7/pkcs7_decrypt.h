/**
 * @file pkcs7_decrypt.h
 * @brief PKCS #7 message decryption
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

#ifndef _PKCS7_DECRYPT_H
#define _PKCS7_DECRYPT_H

//Dependencies
#include "core/crypto.h"
#include "pkcs7/pkcs7_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKCS #7 related functions
error_t pkcs7DecryptEnvelopedData(const Pkcs7EnvelopedData *envelopedData,
   const X509CertInfo *recipientCertInfo, const void *recipientPrivateKey,
   uint8_t *plaintext, size_t *plaintextLen);

error_t pkcs7DecryptKey(const Pkcs7RecipientInfo *recipientInfo,
   const void *recipientPrivateKey, uint8_t *plaintext, size_t *plaintextLen);

error_t pkcs7DecryptData(const Pkcs7EncryptedContentInfo *encryptedContentInfo,
   const uint8_t *key, size_t keyLen, uint8_t *plaintext, size_t *plaintextLen);

error_t pkcs7FindRecipient(const Pkcs7RecipientInfos *recipientInfos,
   const X509CertInfo *recipientCertInfo, Pkcs7RecipientInfo *recipientInfo);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
