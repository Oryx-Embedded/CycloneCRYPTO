/**
 * @file tuple_hash_xof.h
 * @brief TupleHashXOF (TupleHash with arbitrary-length output)
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

#ifndef _TUPLE_HASH_XOF_H
#define _TUPLE_HASH_XOF_H

//Dependencies
#include "core/crypto.h"
#include "xof/cshake.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief TupleHashXOF algorithm context
 **/

typedef struct
{
   CshakeContext cshakeContext;
} TupleHashXofContext;


//TupleHashXOF related functions
error_t tupleHashXofCompute(uint_t strength, const DataFrag *inputFrags,
   uint_t inputNumFrags, const char_t *custom, size_t customLen,
   uint8_t *output, size_t outputLen);

error_t tupleHashXofInit(TupleHashXofContext *context, uint_t strength,
   const char_t *custom, size_t customLen);

void tupleHashXofAbsorb(TupleHashXofContext *context, const void *input,
   size_t length);

void tupleHashXofFinal(TupleHashXofContext *context);

void tupleHashXofSqueeze(TupleHashXofContext *context, uint8_t *output,
   size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
