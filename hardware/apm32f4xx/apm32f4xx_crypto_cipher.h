/**
 * @file apm32f4xx_crypto_cipher.h
 * @brief APM32F4 cipher hardware accelerator
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

#ifndef _APM32F4XX_CRYPTO_CIPHER_H
#define _APM32F4XX_CRYPTO_CIPHER_H

//Dependencies
#include "core/crypto.h"

//Cipher hardware accelerator
#ifndef APM32F4XX_CRYPTO_CIPHER_SUPPORT
   #define APM32F4XX_CRYPTO_CIPHER_SUPPORT DISABLED
#elif (APM32F4XX_CRYPTO_CIPHER_SUPPORT != ENABLED && APM32F4XX_CRYPTO_CIPHER_SUPPORT != DISABLED)
   #error APM32F4XX_CRYPTO_CIPHER_SUPPORT parameter is not valid
#endif

//CRYP Control register
#define CRYP_CTRL_CRYPEN            0x00008000
#define CRYP_CTRL_FFLUSH            0x00004000
#define CRYP_CTRL_KSIZESEL          0x00000300
#define CRYP_CTRL_KSIZESEL_128B     0x00000000
#define CRYP_CTRL_KSIZESEL_192B     0x00000100
#define CRYP_CTRL_KSIZESEL_256B     0x00000200
#define CRYP_CTRL_DTSEL             0x000000C0
#define CRYP_CTRL_DTSEL_32B         0x00000000
#define CRYP_CTRL_DTSEL_16B         0x00000040
#define CRYP_CTRL_DTSEL_8B          0x00000080
#define CRYP_CTRL_DTSEL_1B          0x000000C0
#define CRYP_CTRL_ALGOMSEL          0x00000038
#define CRYP_CTRL_ALGOMSEL_TDES_ECB 0x00000000
#define CRYP_CTRL_ALGOMSEL_TDES_CBC 0x00000008
#define CRYP_CTRL_ALGOMSEL_DES_ECB  0x00000010
#define CRYP_CTRL_ALGOMSEL_DES_CBC  0x00000018
#define CRYP_CTRL_ALGOMSEL_AES_ECB  0x00000020
#define CRYP_CTRL_ALGOMSEL_AES_CBC  0x00000028
#define CRYP_CTRL_ALGOMSEL_AES_CTR  0x00000030
#define CRYP_CTRL_ALGOMSEL_AES_KEY  0x00000038
#define CRYP_CTRL_ALGODIRSEL        0x00000004

//CRYP Status register
#define CRYP_STS_BUSY               0x00000010
#define CRYP_STS_OFFULL             0x00000008
#define CRYP_STS_OFEMPT             0x00000004
#define CRYP_STS_IFFULL             0x00000002
#define CRYP_STS_IFEMPT             0x00000001

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Cipher related functions
error_t crypInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
