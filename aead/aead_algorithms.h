/**
 * @file cipher_algorithms.h
 * @brief Collection of AEAD algorithms
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

#ifndef _AEAD_ALGORITHMS_H
#define _AEAD_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//GCM mode support?
#if (GCM_SUPPORT == ENABLED)
   #include "aead/gcm.h"
#endif

//CCM mode support?
#if (CCM_SUPPORT == ENABLED)
   #include "aead/ccm.h"
#endif

//SIV mode support?
#if (SIV_SUPPORT == ENABLED)
   #include "aead/siv.h"
#endif

//Ascon-AEAD128 support?
#if (ASCON_AEAD128_SUPPORT == ENABLED)
   #include "lwc/ascon_aead128.h"
#endif

//ChaCha20Poly1305 support?
#if (CHACHA20_POLY1305_SUPPORT == ENABLED)
   #include "aead/chacha20_poly1305.h"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief AEAD algorithms
 **/

typedef enum
{
   AEAD_AES_128_GCM           = 1,  ///<RFC 5116
   AEAD_AES_256_GCM           = 2,  ///<RFC 5116
   AEAD_AES_128_CCM           = 3,  ///<RFC 5116
   AEAD_AES_256_CCM           = 4,  ///<RFC 5116
   AEAD_AES_128_GCM_8         = 5,  ///<RFC 5282
   AEAD_AES_256_GCM_8         = 6,  ///<RFC 5282
   AEAD_AES_128_GCM_12        = 7,  ///<RFC 5282
   AEAD_AES_256_GCM_12        = 8,  ///<RFC 5282
   AEAD_AES_128_CCM_SHORT     = 9,  ///<RFC 5282
   AEAD_AES_256_CCM_SHORT     = 10, ///<RFC 5282
   AEAD_AES_128_CCM_SHORT_8   = 11, ///<RFC 5282
   AEAD_AES_256_CCM_SHORT_8   = 12, ///<RFC 5282
   AEAD_AES_128_CCM_SHORT_12  = 13, ///<RFC 5282
   AEAD_AES_256_CCM_SHORT_12  = 14, ///<RFC 5282
   AEAD_AES_SIV_CMAC_256      = 15, ///<RFC 5297
   AEAD_AES_SIV_CMAC_384      = 16, ///<RFC 5297
   AEAD_AES_SIV_CMAC_512      = 17, ///<RFC 5297
   AEAD_AES_128_CCM_8         = 18, ///<RFC 6655
   AEAD_AES_256_CCM_8         = 19, ///<RFC 6655
   AEAD_AES_128_OCB_TAGLEN128 = 20, ///<RFC 7253
   AEAD_AES_128_OCB_TAGLEN96  = 21, ///<RFC 7253
   AEAD_AES_128_OCB_TAGLEN64  = 22, ///<RFC 7253
   AEAD_AES_192_OCB_TAGLEN128 = 23, ///<RFC 7253
   AEAD_AES_192_OCB_TAGLEN96  = 24, ///<RFC 7253
   AEAD_AES_192_OCB_TAGLEN64  = 25, ///<RFC 7253
   AEAD_AES_256_OCB_TAGLEN128 = 26, ///<RFC 7253
   AEAD_AES_256_OCB_TAGLEN96  = 27, ///<RFC 7253
   AEAD_AES_256_OCB_TAGLEN64  = 28, ///<RFC 7253
   AEAD_CHACHA20_POLY1305     = 29, ///<RFC 8439
   AEAD_AES_128_GCM_SIV       = 30, ///<RFC 8452
   AEAD_AES_256_GCM_SIV       = 31, ///<RFC 8452
   AEAD_AEGIS128L             = 32, ///<Draft
   AEAD_AEGIS256              = 33  ///<Draft
} AeadAlgo;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
