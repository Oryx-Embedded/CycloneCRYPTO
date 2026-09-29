/**
 * @file mac_algorithms.h
 * @brief Collection of MAC algorithms
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.6
 **/

#ifndef _MAC_ALGORITHMS_H
#define _MAC_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//CMAC support?
#if (CMAC_SUPPORT == ENABLED)
   #include "mac/cmac.h"
#endif

//HMAC support?
#if (HMAC_SUPPORT == ENABLED)
   #include "mac/hmac.h"
#endif

//GMAC support?
#if (GMAC_SUPPORT == ENABLED)
   #include "mac/gmac.h"
#endif

//KMAC support?
#if (KMAC_SUPPORT == ENABLED)
   #include "mac/kmac.h"
#endif

//XCBC-MAC support?
#if (XCBC_MAC_SUPPORT == ENABLED)
   #include "mac/xcbc_mac.h"
#endif

//BLAKE2b support?
#if (BLAKE2B_SUPPORT == ENABLED)
   #include "mac/blake2b.h"
#endif

//BLAKE2s support?
#if (BLAKE2S_SUPPORT == ENABLED)
   #include "mac/blake2s.h"
#endif

//Poly1305 support?
#if (POLY1305_SUPPORT == ENABLED)
   #include "mac/poly1305.h"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief MAC algorithms
 **/

typedef enum
{
   MAC_ALGO_NONE     = 0,
   MAC_ALGO_CMAC     = 1,
   MAC_ALGO_HMAC     = 2,
   MAC_ALGO_GMAC     = 3,
   MAC_ALGO_KMAC128  = 4,
   MAC_ALGO_KMAC256  = 5,
   MAC_ALGO_XCBC_MAC = 6,
   MAC_ALGO_BLAKE2B  = 7,
   MAC_ALGO_BLAKE2S  = 8,
   MAC_ALGO_POLY1305 = 9
} MacAlgo;


/**
 * @brief Generic MAC algorithm context
 **/

typedef union
{
#if (CMAC_SUPPORT == ENABLED)
   CmacContext cmacContext;
#endif
#if (HMAC_SUPPORT == ENABLED)
   HmacContext hmacContext;
#endif
#if (GMAC_SUPPORT == ENABLED)
   GmacContext gmacContext;
#endif
#if (KMAC_SUPPORT == ENABLED)
   KmacContext kmacContext;
#endif
#if (XCBC_MAC_SUPPORT == ENABLED)
   XcbcMacContext xcbcMacContext;
#endif
#if (BLAKE2B_SUPPORT == ENABLED)
   Blake2bContext blake2bContext;
#endif
#if (BLAKE2S_SUPPORT == ENABLED)
   Blake2sContext blake2sContext;
#endif
#if (POLY1305_SUPPORT == ENABLED)
   Poly1305Context poly1305Context;
#endif
} MacContext;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
