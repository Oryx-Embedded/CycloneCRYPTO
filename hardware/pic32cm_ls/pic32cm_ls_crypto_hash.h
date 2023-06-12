/**
 * @file pic32cm_ls_crypto_hash.h
 * @brief PIC32CM LS00/LS60 hash hardware accelerator
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
 * @version 2.3.0
 **/

#ifndef _PIC32CM_LS_CRYPTO_HASH_H
#define _PIC32CM_LS_CRYPTO_HASH_H

//Dependencies
#include "core/crypto.h"

//Hash hardware accelerator
#ifndef PIC32CM_LS_CRYPTO_HASH_SUPPORT
   #define PIC32CM_LS_CRYPTO_HASH_SUPPORT DISABLED
#elif (PIC32CM_LS_CRYPTO_HASH_SUPPORT != ENABLED && PIC32CM_LS_CRYPTO_HASH_SUPPORT != DISABLED)
   #error PIC32CM_LS_CRYPTO_HASH_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
