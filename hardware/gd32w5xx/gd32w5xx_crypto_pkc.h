/**
 * @file gd32w5xx_crypto_pkc.h
 * @brief GD32W5 public-key hardware accelerator (PKCAU)
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

#ifndef _GD32W5XX_CRYPTO_PKC_H
#define _GD32W5XX_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef GD32W5XX_CRYPTO_PKC_SUPPORT
   #define GD32W5XX_CRYPTO_PKC_SUPPORT DISABLED
#elif (GD32W5XX_CRYPTO_PKC_SUPPORT != ENABLED && GD32W5XX_CRYPTO_PKC_SUPPORT != DISABLED)
   #error GD32W5XX_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//Maximum RSA operand size, in bits
#define PKCAU_MAX_ROS 3136
//Maximum ECC operand size, in bits
#define PKCAU_MAX_EOS 640

//PKCAU RAM
#define PKCAU_RAM ((volatile uint32_t *) (PKCAU_BASE + 0x0400))

//PKCAU RAM offset
#define PKCAU_RAM_OFFSET(n) (((n) - 0x0400) / sizeof(uint32_t))

//Arithmetic multiplication parameters
#define PKCAU_ARITH_MUL_IN_OP_LEN      PKCAU_RAM_OFFSET(0x0404)
#define PKCAU_ARITH_MUL_IN_A           PKCAU_RAM_OFFSET(0x08B4)
#define PKCAU_ARITH_MUL_IN_B           PKCAU_RAM_OFFSET(0x0A44)
#define PKCAU_ARITH_MUL_OUT_R          PKCAU_RAM_OFFSET(0x0BD0)

//Modular exponentiation parameters
#define PKCAU_MOD_EXP_IN_EXP_LEN       PKCAU_RAM_OFFSET(0x0400)
#define PKCAU_MOD_EXP_IN_OP_LEN        PKCAU_RAM_OFFSET(0x0404)
#define PKCAU_MOD_EXP_IN_A             PKCAU_RAM_OFFSET(0x0A44)
#define PKCAU_MOD_EXP_IN_E             PKCAU_RAM_OFFSET(0x0BD0)
#define PKCAU_MOD_EXP_IN_N             PKCAU_RAM_OFFSET(0x0D5C)
#define PKCAU_MOD_EXP_OUT_R            PKCAU_RAM_OFFSET(0x0724)

//RSA CRT exponentiation parameters
#define PKCAU_RSA_CRT_EXP_IN_MOD_LEN   PKCAU_RAM_OFFSET(0x0404)
#define PKCAU_RSA_CRT_EXP_IN_DP        PKCAU_RAM_OFFSET(0x065C)
#define PKCAU_RSA_CRT_EXP_IN_DQ        PKCAU_RAM_OFFSET(0x0BD0)
#define PKCAU_RSA_CRT_EXP_IN_QINV      PKCAU_RAM_OFFSET(0x07EC)
#define PKCAU_RSA_CRT_EXP_IN_P         PKCAU_RAM_OFFSET(0x097C)
#define PKCAU_RSA_CRT_EXP_IN_Q         PKCAU_RAM_OFFSET(0x0D5C)
#define PKCAU_RSA_CRT_EXP_IN_A         PKCAU_RAM_OFFSET(0x0EEC)
#define PKCAU_RSA_CRT_EXP_OUT_R        PKCAU_RAM_OFFSET(0x0724)

//ECC scalar multiplication parameters
#define PKCAU_ECC_MUL_IN_SCALAR_LEN    PKCAU_RAM_OFFSET(0x0400)
#define PKCAU_ECC_MUL_IN_MOD_LEN       PKCAU_RAM_OFFSET(0x0404)
#define PKCAU_ECC_MUL_IN_A_SIGN        PKCAU_RAM_OFFSET(0x0408)
#define PKCAU_ECC_MUL_IN_A             PKCAU_RAM_OFFSET(0x040C)
#define PKCAU_ECC_MUL_IN_P             PKCAU_RAM_OFFSET(0x0460)
#define PKCAU_ECC_MUL_IN_K             PKCAU_RAM_OFFSET(0x0508)
#define PKCAU_ECC_MUL_IN_X             PKCAU_RAM_OFFSET(0x055C)
#define PKCAU_ECC_MUL_IN_Y             PKCAU_RAM_OFFSET(0x05B0)
#define PKCAU_ECC_MUL_OUT_X            PKCAU_RAM_OFFSET(0x055C)
#define PKCAU_ECC_MUL_OUT_Y            PKCAU_RAM_OFFSET(0x05B0)

//ECDSA sign parameters
#define PKCAU_ECDSA_SIGN_IN_ORDER_LEN  PKCAU_RAM_OFFSET(0x0400)
#define PKCAU_ECDSA_SIGN_IN_MOD_LEN    PKCAU_RAM_OFFSET(0x0404)
#define PKCAU_ECDSA_SIGN_IN_A_SIGN     PKCAU_RAM_OFFSET(0x0408)
#define PKCAU_ECDSA_SIGN_IN_A          PKCAU_RAM_OFFSET(0x040C)
#define PKCAU_ECDSA_SIGN_IN_P          PKCAU_RAM_OFFSET(0x0460)
#define PKCAU_ECDSA_SIGN_IN_K          PKCAU_RAM_OFFSET(0x0508)
#define PKCAU_ECDSA_SIGN_IN_GX         PKCAU_RAM_OFFSET(0x055C)
#define PKCAU_ECDSA_SIGN_IN_GY         PKCAU_RAM_OFFSET(0x05B0)
#define PKCAU_ECDSA_SIGN_IN_Z          PKCAU_RAM_OFFSET(0x0DE8)
#define PKCAU_ECDSA_SIGN_IN_D          PKCAU_RAM_OFFSET(0x0E3C)
#define PKCAU_ECDSA_SIGN_IN_N          PKCAU_RAM_OFFSET(0x0E94)
#define PKCAU_ECDSA_SIGN_OUT_R         PKCAU_RAM_OFFSET(0x0700)
#define PKCAU_ECDSA_SIGN_OUT_S         PKCAU_RAM_OFFSET(0x0754)
#define PKCAU_ECDSA_SIGN_OUT_ERROR     PKCAU_RAM_OFFSET(0x0EE8)

//ECDSA verification parameters
#define PKCAU_ECDSA_VERIF_IN_ORDER_LEN PKCAU_RAM_OFFSET(0x0404)
#define PKCAU_ECDSA_VERIF_IN_MOD_LEN   PKCAU_RAM_OFFSET(0x04B4)
#define PKCAU_ECDSA_VERIF_IN_A_SIGN    PKCAU_RAM_OFFSET(0x045C)
#define PKCAU_ECDSA_VERIF_IN_A         PKCAU_RAM_OFFSET(0x0460)
#define PKCAU_ECDSA_VERIF_IN_P         PKCAU_RAM_OFFSET(0x04B8)
#define PKCAU_ECDSA_VERIF_IN_GX        PKCAU_RAM_OFFSET(0x05E8)
#define PKCAU_ECDSA_VERIF_IN_GY        PKCAU_RAM_OFFSET(0x063C)
#define PKCAU_ECDSA_VERIF_IN_S         PKCAU_RAM_OFFSET(0x0A44)
#define PKCAU_ECDSA_VERIF_IN_N         PKCAU_RAM_OFFSET(0x0D5C)
#define PKCAU_ECDSA_VERIF_IN_QX        PKCAU_RAM_OFFSET(0x0F40)
#define PKCAU_ECDSA_VERIF_IN_QY        PKCAU_RAM_OFFSET(0x0F94)
#define PKCAU_ECDSA_VERIF_IN_Z         PKCAU_RAM_OFFSET(0x0FE8)
#define PKCAU_ECDSA_VERIF_IN_R         PKCAU_RAM_OFFSET(0x1098)
#define PKCAU_ECDSA_VERIF_OUT_RES      PKCAU_RAM_OFFSET(0x05B0)

//PKCAU status codes
#define PKCAU_STATUS_SUCCESS 0x00000000
#define PKCAU_STATUS_INVALID 0xFFFFFFFF

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PKCAU related functions
error_t pkcauInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
