/**
 * @file prng_algorithms.h
 * @brief Collection of PRNG algorithms
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
 * @version 2.5.4
 **/

#ifndef _PRNG_ALGORITHMS_H
#define _PRNG_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//Hash_DRBG PRNG support?
#if (HASH_DRBG_SUPPORT == ENABLED)
   #include "rng/hash_drbg.h"
#endif

//HMAC_DRBG PRNG support?
#if (HMAC_DRBG_SUPPORT == ENABLED)
   #include "rng/hmac_drbg.h"
#endif

//CTR_DRBG PRNG support?
#if (CTR_DRBG_SUPPORT == ENABLED)
   #include "rng/ctr_drbg.h"
#endif

//XDRBG PRNG support?
#if (XDRBG_SUPPORT == ENABLED)
   #include "rng/xdrbg.h"
#endif

//Yarrow PRNG support?
#if (YARROW_SUPPORT == ENABLED)
   #include "rng/yarrow.h"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Generic PRNG algorithm context
 **/

typedef union
{
#if (HASH_DRBG_SUPPORT == ENABLED)
   HashDrbgContext hashDrbgContext;
#endif
#if (HMAC_DRBG_SUPPORT == ENABLED)
   HmacDrbgContext hmacDrbgContext;
#endif
#if (CTR_DRBG_SUPPORT == ENABLED)
   CtrDrbgContext ctrDrbgContext;
#endif
#if (XDRBG_SUPPORT == ENABLED)
   XdrbgContext xdrbgContext;
#endif
#if (YARROW_SUPPORT == ENABLED)
   YarrowContext yarrowContext;
#endif
} PrngContext;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
