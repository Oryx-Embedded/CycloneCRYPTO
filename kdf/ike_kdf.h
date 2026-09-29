/**
 * @file ike_kdf.h
 * @brief IKEv2 key derivation functions
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

#ifndef _IKE_KDF_H
#define _IKE_KDF_H

//Dependencies
#include "core/crypto.h"
#include "mac/mac_algorithms.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief IKE PRF algorithm context
 **/

typedef struct
{
   MacAlgo macAlgo;
   MacContext macContext;
   size_t outputLen;
} IkePrfContext;


//IKE KDF related functions
error_t ikePrf(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const uint8_t *data, size_t dataLen, uint8_t *output);

error_t ikePrfEx(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const DataFrag *dataFrags, uint_t dataNumFrags, uint8_t *output);

error_t ikePrfPlus(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const uint8_t *data, size_t dataLen, uint8_t *output,
   size_t outputLen);

error_t ikePrfPlusEx(MacAlgo macAlgo, const HashAlgo *hashAlgo,
   const CipherAlgo *cipherAlgo, const uint8_t *key, size_t keyLen,
   const DataFrag *dataFrags, uint_t dataNumFrags, uint8_t *output,
   size_t outputLen);

error_t ikePrfInit(IkePrfContext *context, MacAlgo macAlgo,
   const HashAlgo *hashAlgo, const CipherAlgo *cipherAlgo, const uint8_t *key,
   size_t keyLen);

void ikePrfUpdate(IkePrfContext *context, const uint8_t *data, size_t dataLen);
error_t ikePrfFinal(IkePrfContext *context, uint8_t *output, size_t outputLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
