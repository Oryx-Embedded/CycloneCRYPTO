/**
 * @file pic32mz_crypto_pkc.h
 * @brief PIC32MZ W1 public-key hardware accelerator (BA414E)
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

#ifndef _PIC32MZ_CRYPTO_PKC_H
#define _PIC32MZ_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef PIC32MZ_CRYPTO_PKC_SUPPORT
   #define PIC32MZ_CRYPTO_PKC_SUPPORT DISABLED
#elif (PIC32MZ_CRYPTO_PKC_SUPPORT != ENABLED && PIC32MZ_CRYPTO_PKC_SUPPORT != DISABLED)
   #error PIC32MZ_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//Point to the specified SCM memory slot
#define BA414E_GET_SCM_SLOT(n) ((uint32_t *) __CRYPTO1SCM_BASE + ((n) * 16))

//Modular arithmetic operands
#define BA414E_MOD_SLOT_P          0
#define BA414E_MOD_SLOT_A          1
#define BA414E_MOD_SLOT_B          2
#define BA414E_MOD_SLOT_C          3

//RSA modular exponentiation operands
#define BA414E_RSA_MOD_EXP_SLOT_P  0
#define BA414E_RSA_MOD_EXP_SLOT_A  1
#define BA414E_RSA_MOD_EXP_SLOT_E  2
#define BA414E_RSA_MOD_EXP_SLOT_C  3

//ECC operands
#define BA414E_ECC_SLOT_P          0
#define BA414E_ECC_SLOT_N          1
#define BA414E_ECC_SLOT_GX         2
#define BA414E_ECC_SLOT_GY         3
#define BA414E_ECC_SLOT_A          4
#define BA414E_ECC_SLOT_B          5
#define BA414E_ECC_SLOT_P1X        6
#define BA414E_ECC_SLOT_P1Y        7
#define BA414E_ECC_SLOT_P2X        8
#define BA414E_ECC_SLOT_P2Y        9
#define BA414E_ECC_SLOT_P3X        10
#define BA414E_ECC_SLOT_P3Y        11
#define BA414E_ECC_SLOT_K          12

//ECDSA operands
#define BA414E_ECDSA_SLOT_P        0
#define BA414E_ECDSA_SLOT_N        1
#define BA414E_ECDSA_SLOT_GX       2
#define BA414E_ECDSA_SLOT_GY       3
#define BA414E_ECDSA_SLOT_A        4
#define BA414E_ECDSA_SLOT_B        5
#define BA414E_ECDSA_SLOT_D        6
#define BA414E_ECDSA_SLOT_K        7
#define BA414E_ECDSA_SLOT_QX       8
#define BA414E_ECDSA_SLOT_QY       9
#define BA414E_ECDSA_SLOT_R        10
#define BA414E_ECDSA_SLOT_S        11
#define BA414E_ECDSA_SLOT_H        12
#define BA414E_ECDSA_SLOT_W        13
#define BA414E_ECDSA_SLOT_P1X      14
#define BA414E_ECDSA_SLOT_P1Y      15

//Curve25519 operands
#define BA414E_CURVE25519_SLOT_P   0
#define BA414E_CURVE25519_SLOT_X1  2
#define BA414E_CURVE25519_SLOT_A24 3
#define BA414E_CURVE25519_SLOT_K   4
#define BA414E_CURVE25519_SLOT_X3  6

//Ed25519 operands
#define BA414E_ED25519_SLOT_P      0
#define BA414E_ED25519_SLOT_D2     1
#define BA414E_ED25519_SLOT_PX     2
#define BA414E_ED25519_SLOT_PY     3
#define BA414E_ED25519_SLOT_E      4
#define BA414E_ED25519_SLOT_CX     6
#define BA414E_ED25519_SLOT_CY     7

//OPSIZE bitfield
#define PKCOMMAND_OPSIZE_128B             0x00000200
#define PKCOMMAND_OPSIZE_256B             0x00000400
#define PKCOMMAND_OPSIZE_512B             0x00000800

//OPERATION bitfield
#define PKCOMMAND_OP_MOD_ADD              0x00000001
#define PKCOMMAND_OP_MOD_SUB              0x00000002
#define PKCOMMAND_OP_MOD_MUL_ODD          0x00000003
#define PKCOMMAND_OP_MOD_RED_ODD          0x00000004
#define PKCOMMAND_OP_MOD_DIV_ODD          0x00000005
#define PKCOMMAND_OP_MOD_INV_ODD          0x00000006
#define PKCOMMAND_OP_MUL                  0x00000008
#define PKCOMMAND_OP_MOD_INV_EVEN         0x00000009
#define PKCOMMAND_OP_RSA_MOD_EXP          0x00000010
#define PKCOMMAND_OP_RSA_PRIV_KEY_GEN     0x00000011
#define PKCOMMAND_OP_ECC_POINT_DBL        0x00000020
#define PKCOMMAND_OP_ECC_POINT_ADD        0x00000021
#define PKCOMMAND_OP_ECC_POINT_MUL        0x00000022
#define PKCOMMAND_OP_ECC_CHECK_AB         0x00000023
#define PKCOMMAND_OP_ECC_POINT_N          0x00000024
#define PKCOMMAND_OP_ECC_CHECK_RS         0x00000025
#define PKCOMMAND_OP_ECC_CHECK_POINT      0x00000026
#define PKCOMMAND_OP_CURVE25519_POINT_MUL 0x00000028
#define PKCOMMAND_OP_ED25519_XRECOVER     0x00000029
#define PKCOMMAND_OP_ED25519_SCALAR_MUL   0x0000002A
#define PKCOMMAND_OP_ED25519_CHECK_VALID  0x0000002B
#define PKCOMMAND_OP_ED25519_CHECK_POINT  0x0000002C
#define PKCOMMAND_OP_ECDSA_SIGN_GEN       0x00000030
#define PKCOMMAND_OP_ECDSA_SIGN_VERIFY    0x00000031
#define PKCOMMAND_OP_ECDSA_PARAMS_VALID   0x00000032

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//BA414E related functions
error_t ba414eInit(void);
void ba414eClearScm(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
