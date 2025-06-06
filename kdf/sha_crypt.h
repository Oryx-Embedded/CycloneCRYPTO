/**
 * @file sha_crypt.h
 * @brief Unix crypt using SHA-256 and SHA-512
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

#ifndef _SHA_CRYPT_H
#define _SHA_CRYPT_H

//Dependencies
#include "core/crypto.h"

//Minimum number of rounds
#define SHA_CRYPT_MIN_ROUNDS 1000
//Maximum number of rounds
#define SHA_CRYPT_MAX_ROUNDS 999999999
//Default number of rounds
#define SHA_CRYPT_DEFAULT_ROUNDS 5000

//Maximum length of the salt string
#define SHA_CRYPT_MAX_SALT_LEN 16

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SHA-crypt related functions
error_t shaCrypt(const HashAlgo *hashAlgo, const char_t *password,
   const char_t *salt, char_t *output, size_t *outputLen);

size_t shaCryptEncodeBase64(const HashAlgo *hashAlgo, const uint8_t *input,
   uint8_t *output);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
