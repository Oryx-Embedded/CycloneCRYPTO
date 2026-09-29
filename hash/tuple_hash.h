/**
 * @file tuple_hash.h
 * @brief TupleHash hash function
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

#ifndef _TUPLE_HASH_H
#define _TUPLE_HASH_H

//Dependencies
#include "core/crypto.h"
#include "xof/cshake.h"

//Application specific context
#ifndef TUPLE_HASH_CONTEXT_PRIVATE
   #define TUPLE_HASH_CONTEXT_PRIVATE
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief TupleHash algorithm context
 **/

typedef struct
{
   CshakeContext cshakeContext;
   TUPLE_HASH_CONTEXT_PRIVATE
} TupleHashContext;


//TupleHash related functions
error_t tupleHashCompute(uint_t strength, const DataFrag *dataFrags,
   uint_t dataNumFrags, const char_t *custom, size_t customLen,
   uint8_t *digest, size_t digestLen);

error_t tupleHashInit(TupleHashContext *context, uint_t strength,
   const char_t *custom, size_t customLen);

void tupleHashUpdate(TupleHashContext *context, const void *data,
   size_t length);

void tupleHashFinal(TupleHashContext *context, uint8_t *digest, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
