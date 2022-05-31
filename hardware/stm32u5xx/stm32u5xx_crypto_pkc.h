/**
 * @file stm32u5xx_crypto_pkc.h
 * @brief STM32U5 public-key hardware accelerator (PKA)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.1.6
 **/

#ifndef _STM32U5XX_CRYPTO_PKC_H
#define _STM32U5XX_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef STM32U5XX_CRYPTO_PKC_SUPPORT
   #define STM32U5XX_CRYPTO_PKC_SUPPORT DISABLED
#elif (STM32U5XX_CRYPTO_PKC_SUPPORT != ENABLED && STM32U5XX_CRYPTO_PKC_SUPPORT != DISABLED)
   #error STM32U5XX_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//Maximum RSA operand size, in bits
#define PKA_MAX_ROS 4160
//Maximum ECC operand size, in bits
#define PKA_MAX_EOS 640

//PKA operation modes
#define PKA_CR_MODE_MODULAR_EXP           0x00
#define PKA_CR_MODE_MONTGOMERY_PARAM      0x01
#define PKA_CR_MODE_MODULAR_EXP_FAST_MODE 0x02
#define PKA_CR_MODE_MODULAR_EXP_PROTECT   0x03
#define PKA_CR_MODE_RSA_CRT_EXP           0x07
#define PKA_CR_MODE_MODULAR_INV           0x08
#define PKA_CR_MODE_ARITHMETIC_ADD        0x09
#define PKA_CR_MODE_ARITHMETIC_SUB        0x0A
#define PKA_CR_MODE_ARITHMETIC_MUL        0x0B
#define PKA_CR_MODE_COMPARISON            0x0C
#define PKA_CR_MODE_MODULAR_RED           0x0D
#define PKA_CR_MODE_MODULAR_ADD           0x0E
#define PKA_CR_MODE_MODULAR_SUB           0x0F
#define PKA_CR_MODE_MONTGOMERY_MUL        0x10
#define PKA_CR_MODE_ECC_MUL               0x20
#define PKA_CR_MODE_ECC_COMPLETE_ADD      0x23
#define PKA_CR_MODE_ECDSA_SIGN            0x24
#define PKA_CR_MODE_ECDSA_VERIFY          0x26
#define PKA_CR_MODE_DOUBLE_BASE_LADDER    0x27
#define PKA_CR_MODE_POINT_CHECK           0x28
#define PKA_CR_MODE_ECC_PROJECTIVE_AFF    0x2F

//PKA status codes
#define PKA_STATUS_SUCCESS 0xD60D
#define PKA_STATUS_INVALID 0x0000

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKA related functions
error_t pkaInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
