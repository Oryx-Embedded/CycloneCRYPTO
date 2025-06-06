/**
 * @file xof_algorithms.h
 * @brief Collection of XOF algorithms
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

#ifndef _XOF_ALGORITHMS_H
#define _XOF_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//Keccak support?
#if (KECCAK_SUPPORT == ENABLED)
   #include "xof/keccak.h"
#endif

//SHAKE support?
#if (SHAKE_SUPPORT == ENABLED)
   #include "xof/shake.h"
#endif

//cSHAKE support?
#if (CSHAKE_SUPPORT == ENABLED)
   #include "xof/cshake.h"
#endif

//Ascon-XOF128 support?
#if (ASCON_XOF128_SUPPORT == ENABLED)
   #include "lwc/ascon_xof128.h"
#endif

//Ascon-CXOF128 support?
#if (ASCON_CXOF128_SUPPORT == ENABLED)
   #include "lwc/ascon_cxof128.h"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Generic XOF algorithm context
 **/

typedef union
{
#if (KECCAK_SUPPORT == ENABLED)
   KeccakContext keccakContext;
#endif
#if (SHAKE_SUPPORT == ENABLED)
   ShakeContext shakeContext;
#endif
#if (CSHAKE_SUPPORT == ENABLED)
   CshakeContext cshakeContext;
#endif
#if (ASCON_XOF128_SUPPORT == ENABLED)
   AsconXof128Context asconXof128Context;
#endif
#if (ASCON_CXOF128_SUPPORT == ENABLED)
   AsconCxof128Context asconCxof128Context;
#endif
} XofContext;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
