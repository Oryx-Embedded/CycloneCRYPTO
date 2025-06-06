/**
 * @file ra8_crypto_pkc.h
 * @brief RA8 public-key hardware accelerator
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

#ifndef _RA8_CRYPTO_PKC_H
#define _RA8_CRYPTO_PKC_H

//Dependencies
#include "hw_sce_private.h"
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef RA8_CRYPTO_PKC_SUPPORT
   #define RA8_CRYPTO_PKC_SUPPORT DISABLED
#elif (RA8_CRYPTO_PKC_SUPPORT != ENABLED && RA8_CRYPTO_PKC_SUPPORT != DISABLED)
   #error RA8_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RSA primitive arguments
 **/

typedef struct
{
   uint32_t m[128];
   uint32_t c[128];
   uint32_t key[256];
   uint32_t wrappedKey[300];
} Ra8RsaArgs;


/**
 * @brief EC primitive arguments
 **/

typedef struct
{
   uint32_t g[40];
   uint32_t d[20];
   uint32_t q[40];
   uint32_t digest[20];
   uint32_t signature[40];
   uint32_t wrappedKey[100];
} Ra8EcArgs;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
