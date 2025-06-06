/**
 * @file apm32f4xx_crypto_hash.h
 * @brief APM32F4 hash hardware accelerator
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

#ifndef _APM32F4XX_CRYPTO_HASH_H
#define _APM32F4XX_CRYPTO_HASH_H

//Dependencies
#include "core/crypto.h"

//Hash hardware accelerator
#ifndef APM32F4XX_CRYPTO_HASH_SUPPORT
   #define APM32F4XX_CRYPTO_HASH_SUPPORT DISABLED
#elif (APM32F4XX_CRYPTO_HASH_SUPPORT != ENABLED && APM32F4XX_CRYPTO_HASH_SUPPORT != DISABLED)
   #error APM32F4XX_CRYPTO_HASH_SUPPORT parameter is not valid
#endif

//HASH Control register
#define HASH_CTRL_LKEYSEL     0x00010000
#define HASH_CTRL_DINNEMPT    0x00001000
#define HASH_CTRL_WNUM        0x00000F00
#define HASH_CTRL_ALGSEL      0x00000080
#define HASH_CTRL_ALGSEL_SHA1 0x00000000
#define HASH_CTRL_ALGSEL_MD5  0x00000080
#define HASH_CTRL_MODESEL     0x00000040
#define HASH_CTRL_DTYPE       0x00000030
#define HASH_CTRL_DTYPE_32B   0x00000000
#define HASH_CTRL_DTYPE_16B   0x00000010
#define HASH_CTRL_DTYPE_8B    0x00000020
#define HASH_CTRL_DTYPE_1B    0x00000030
#define HASH_CTRL_DMAEN       0x00000008
#define HASH_CTRL_INITCAL     0x00000004

//HASH Status register
#define HASH_STS_BUSY         0x00000008
#define HASH_STS_DMA          0x00000004
#define HASH_STS_DCALCINT     0x00000002
#define HASH_STS_INDATAINT    0x00000001

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Hash related functions
error_t hashInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
