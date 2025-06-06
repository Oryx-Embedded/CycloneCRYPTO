/**
 * @file max32690_crypto_pkc.h
 * @brief MAX32690 public-key hardware accelerator
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

#ifndef _MAX32690_CRYPTO_PKC_H
#define _MAX32690_CRYPTO_PKC_H

//Dependencies
#include "core/crypto.h"

//Public-key hardware accelerator
#ifndef MAX32690_CRYPTO_PKC_SUPPORT
   #define MAX32690_CRYPTO_PKC_SUPPORT DISABLED
#elif (MAX32690_CRYPTO_PKC_SUPPORT != ENABLED && MAX32690_CRYPTO_PKC_SUPPORT != DISABLED)
   #error MAX32690_CRYPTO_PKC_SUPPORT parameter is not valid
#endif

//MAA memory instances
#define CTB_MAA_MEM_INSTANCE_0 0x0100
#define CTB_MAA_MEM_INSTANCE_1 0x0200
#define CTB_MAA_MEM_INSTANCE_2 0x0300
#define CTB_MAA_MEM_INSTANCE_3 0x0400
#define CTB_MAA_MEM_INSTANCE_4 0x0500
#define CTB_MAA_MEM_INSTANCE_5 0x0600

//Cryptographic Control register
#define CTB_CTRL_MAA_DONE_Pos             28
#define TB_CTRL_MAA_DONE_Msk              0x10000000
#define TB_CTRL_MAA_DONE(n)               (((n) << CTB_CTRL_MAA_DONE_Pos) & TB_CTRL_MAA_DONE_Msk)

//MAA Control register
#define CTB_MAA_CTRL_TMA_Pos              28
#define CTB_MAA_CTRL_TMA_Msk              0xF0000000
#define CTB_MAA_CTRL_TMA(n)               (((n) << CTB_MAA_CTRL_TMA_Pos) & CTB_MAA_CTRL_TMA_Msk)

#define CTB_MAA_CTRL_RMA_Pos              24
#define CTB_MAA_CTRL_RMA_Msk              0x0F000000
#define CTB_MAA_CTRL_RMA(n)               (((n) << CTB_MAA_CTRL_RMA_Pos) & CTB_MAA_CTRL_RMA_Msk)

#define CTB_MAA_CTRL_BMA_Pos              20
#define CTB_MAA_CTRL_BMA_Msk              0x00F00000
#define CTB_MAA_CTRL_BMA(n)               (((n) << CTB_MAA_CTRL_BMA_Pos) & CTB_MAA_CTRL_BMA_Msk)

#define CTB_MAA_CTRL_AMA_Pos              16
#define CTB_MAA_CTRL_AMA_Msk              0x000F0000
#define CTB_MAA_CTRL_AMA(n)               (((n) << CTB_MAA_CTRL_AMA_Pos) & CTB_MAA_CTRL_AMA_Msk)

#define CTB_MAA_CTRL_MMS_Pos              14
#define CTB_MAA_CTRL_MMS_Msk              0x0000C000
#define CTB_MAA_CTRL_MMS(n)               (((n) << CTB_MAA_CTRL_MMS_Pos) & CTB_MAA_CTRL_MMS_Msk)

#define CTB_MAA_CTRL_EMS_Pos              12
#define CTB_MAA_CTRL_EMS_Msk              0x00003000
#define CTB_MAA_CTRL_EMS(n)               (((n) << CTB_MAA_CTRL_EMS_Pos) & CTB_MAA_CTRL_EMS_Msk)

#define CTB_MAA_CTRL_BMS_Pos              10
#define CTB_MAA_CTRL_BMS_Msk              0x00000C00
#define CTB_MAA_CTRL_BMS(n)               (((n) << CTB_MAA_CTRL_BMS_Pos) & CTB_MAA_CTRL_BMS_Msk)

#define CTB_MAA_CTRL_AMS_Pos              8
#define CTB_MAA_CTRL_AMS_Msk              0x00000300
#define CTB_MAA_CTRL_AMS(n)               (((n) << CTB_MAA_CTRL_AMS_Pos) & CTB_MAA_CTRL_AMS_Msk)

#define CTB_MAA_CTRL_OPT_Pos              4
#define CTB_MAA_CTRL_OPT_Msk              0x00000010
#define CTB_MAA_CTRL_OPT(n)               (((n) << CTB_MAA_CTRL_OPT_Pos) & CTB_MAA_CTRL_OPT_Msk)

#define CTB_MAA_CTRL_CALC_Pos             1
#define CTB_MAA_CTRL_CALC_Msk             0x0000000E
#define CTB_MAA_CTRL_CALC_MOD_EXP_Val     0
#define CTB_MAA_CTRL_CALC_MOD_SQR_Val     1
#define CTB_MAA_CTRL_CALC_MOD_MUL_Val     2
#define CTB_MAA_CTRL_CALC_MOD_SQR_MUL_Val 3
#define CTB_MAA_CTRL_CALC_MOD_ADD_Val     4
#define CTB_MAA_CTRL_CALC_MOD_SUB_Val     5
#define CTB_MAA_CTRL_CALC(n)              (((n) << CTB_MAA_CTRL_CALC_Pos) & CTB_MAA_CTRL_CALC_Msk)

#define CTB_MAA_CTRL_START_Pos            0
#define CTB_MAA_CTRL_START_Msk            0x00000001
#define CTB_MAA_CTRL_START(n)             (((n) << CTB_MAA_CTRL_START_Pos) & CTB_MAA_CTRL_START_Msk)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
