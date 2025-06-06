/**
 * @file pkcs5_decrypt.h
 * @brief PKCS #5 decryption routines
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

#ifndef _PKCS5_DECRYPT_H
#define _PKCS5_DECRYPT_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"
#include "pkix/pkcs5_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKCS #5 related functions
error_t pkcs5Decrypt(const X509AlgoId *encryptionAlgoId,
   const char_t *password, const uint8_t *ciphertext, size_t ciphertextLen,
   uint8_t *plaintext, size_t *plaintextLen);

error_t pkcs5DecryptPbes1(const X509AlgoId *encryptionAlgoId,
   const char_t *password, const uint8_t *ciphertext, size_t ciphertextLen,
   uint8_t *plaintext, size_t *plaintextLen);

error_t pkcs5DecryptPbes2(const X509AlgoId *encryptionAlgoId,
   const char_t *password, const uint8_t *ciphertext, size_t ciphertextLen,
   uint8_t *plaintext, size_t *plaintextLen);

error_t pkcs5ParsePbes1Params(const uint8_t *data, size_t length,
   Pkcs5Pbes1Params *pbes1Params);

error_t pkcs5ParsePbes2Params(const uint8_t *data, size_t length,
   Pkcs5Pbes2Params *pbes2Params);

error_t pkcs5ParseKeyDerivationFunc(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs5KeyDerivationFunc *keyDerivationFunc);

error_t pkcs5ParsePbkdf2Params(const uint8_t *data, size_t length,
   Pkcs5KeyDerivationFunc *keyDerivationFunc);

error_t pkcs5ParseEncryptionScheme(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs5EncryptionScheme *encryptionScheme);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
