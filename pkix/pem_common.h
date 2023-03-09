/**
 * @file pem_common.h
 * @brief PEM common definitions
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

#ifndef _PEM_COMMON_H
#define _PEM_COMMON_H

//Dependencies
#include "core/crypto.h"

//Encrypted private key support
#ifndef PEM_ENCRYPTED_KEY_SUPPORT
   #define PEM_ENCRYPTED_KEY_SUPPORT DISABLED
#elif (PEM_ENCRYPTED_KEY_SUPPORT != ENABLED && PEM_ENCRYPTED_KEY_SUPPORT != DISABLED)
   #error PEM_ENCRYPTED_KEY_SUPPORT parameter is not valid
#endif

//DES encryption support (insecure)
#ifndef PEM_DES_SUPPORT
   #define PEM_DES_SUPPORT DISABLED
#elif (PEM_DES_SUPPORT != ENABLED && PEM_DES_SUPPORT != DISABLED)
   #error PEM_DES_SUPPORT parameter is not valid
#endif

//Triple DES encryption support (weak)
#ifndef PEM_3DES_SUPPORT
   #define PEM_3DES_SUPPORT DISABLED
#elif (PEM_3DES_SUPPORT != ENABLED && PEM_3DES_SUPPORT != DISABLED)
   #error PEM_3DES_SUPPORT parameter is not valid
#endif

//AES encryption support
#ifndef PEM_AES_SUPPORT
   #define PEM_AES_SUPPORT ENABLED
#elif (PEM_AES_SUPPORT != ENABLED && PEM_AES_SUPPORT != DISABLED)
   #error PEM_AES_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief String representation
 **/

typedef struct
{
   const char_t *value;
   size_t length;
} PemString;


/**
 * @brief "Proc-Type" header field
 **/

typedef struct
{
   PemString version;
   PemString type;
} PemProcType;


/**
 * @brief "DEK-Info" header field
 **/

typedef struct
{
   PemString algo;
   PemString iv;
} PemDekInfo;


/**
 * @brief PEM encapsulated header
 **/

typedef struct
{
   PemProcType procType;
   PemDekInfo dekInfo;
} PemHeader;


//PEM related functions
error_t pemDecodeFile(const char_t *input, size_t inputLen, const char_t *label,
   uint8_t *output, size_t *outputLen, PemHeader *header, size_t *consumed);

error_t pemEncodeFile(const void *input, size_t inputLen, const char_t *label,
   char_t *output, size_t *outputLen);

error_t pemParseHeader(const char_t *input, size_t inputLen,
   PemHeader *header, size_t *consumed);

void pemParseHeaderField(PemString *line, PemHeader *header);

int_t pemFindTag(const char_t *input, size_t inputLen, const char_t *tag1,
   const char_t *tag2, const char_t *tag3);

int_t pemFindChar(const PemString *s, char_t c);
bool_t pemCompareString(const PemString *string, const char_t *value);
bool_t pemTokenizeString(PemString *s, char_t c, PemString *token);
void pemTrimWhitespace(PemString *s);

const CipherAlgo *pemGetCipherAlgo(const PemString *algo);
uint_t pemGetKeyLength(const PemString *algo);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
