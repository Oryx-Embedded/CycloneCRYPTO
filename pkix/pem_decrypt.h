/**
 * @file pem_decrypt.h
 * @brief PEM file decryption
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.2.4
 **/

#ifndef _PEM_DECRYPT_H
#define _PEM_DECRYPT_H

//Dependencies
#include "core/crypto.h"
#include "pkix/pem_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PEM related functions
error_t pemDecryptPrivateKey(const char_t *input, size_t inputLen,
   const char_t *password, char_t *output, size_t *outputLen);

error_t pemDecryptMessage(const PemHeader *header, const char_t *password,
   const uint8_t *ciphertext, size_t ciphertextLen, uint8_t *plaintext,
   size_t *plaintextLen);

error_t pemFormatIv(const PemHeader *header, uint8_t *iv, size_t ivLen);

error_t pemKdf(const char_t *p, size_t pLen, const uint8_t *s, size_t sLen,
   uint8_t *dk, size_t dkLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
