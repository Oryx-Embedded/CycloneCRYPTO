/**
 * @file stm32l5xx_crypto_pkc.h
 * @brief STM32L5 public-key hardware accelerator (PKA)
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
 * @version 2.1.4
 **/

#ifndef _STM32L5XX_CRYPTO_PKC_H
#define _STM32L5XX_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef STM32L5XX_CRYPTO_PKC_SUPPORT
   #define STM32L5XX_CRYPTO_PKC_SUPPORT DISABLED
#elif (STM32L5XX_CRYPTO_PKC_SUPPORT != ENABLED && STM32L5XX_CRYPTO_PKC_SUPPORT != DISABLED)
   #error STM32L5XX_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//Maximum RSA operand size, in bytes
#define STM32L5XX_MAX_ROS 392
//Maximum ECC operand size, in bytes
#define STM32L5XX_MAX_EOS 80

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RSA primitive arguments
 **/

typedef struct
{
   uint8_t a[STM32L5XX_MAX_ROS];
   uint8_t d[STM32L5XX_MAX_ROS];
   uint8_t e[STM32L5XX_MAX_ROS];
   uint8_t n[STM32L5XX_MAX_ROS];
   uint8_t p[STM32L5XX_MAX_ROS];
   uint8_t q[STM32L5XX_MAX_ROS];
   uint8_t dp[STM32L5XX_MAX_ROS];
   uint8_t dq[STM32L5XX_MAX_ROS];
   uint8_t qinv[STM32L5XX_MAX_ROS];
} Stm32l5xxRsaArgs;


/**
 * @brief ECC primitive arguments
 **/

typedef struct
{
   uint8_t p[STM32L5XX_MAX_EOS];
   uint8_t a[STM32L5XX_MAX_EOS];
   uint8_t gx[STM32L5XX_MAX_EOS];
   uint8_t gy[STM32L5XX_MAX_EOS];
   uint8_t q[STM32L5XX_MAX_EOS];
   uint8_t h[STM32L5XX_MAX_EOS];
   uint8_t k[STM32L5XX_MAX_EOS];
   uint8_t d[STM32L5XX_MAX_EOS];
   uint8_t qx[STM32L5XX_MAX_EOS];
   uint8_t qy[STM32L5XX_MAX_EOS];
   uint8_t r[STM32L5XX_MAX_EOS];
   uint8_t s[STM32L5XX_MAX_EOS];
} Stm32l5xxEccArgs;


//PKA related functions
error_t pkaInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
