/**
 * @file kem.h
 * @brief Key encapsulation mechanism (KEM)
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

#ifndef _KEM_H
#define _KEM_H

//Dependencies
#include "core/crypto.h"

//ML-KEM-512 key encapsulation mechanism supported?
#if (MLKEM512_SUPPORT == ENABLED)
   #include "pqc/mlkem512.h"
#endif

//ML-KEM-768 key encapsulation mechanism supported?
#if (MLKEM768_SUPPORT == ENABLED)
   #include "pqc/mlkem768.h"
#endif

//ML-KEM-1024 key encapsulation mechanism supported?
#if (MLKEM1024_SUPPORT == ENABLED)
   #include "pqc/mlkem1024.h"
#endif

//Streamlined NTRU Prime 761 KEM supported?
#if (SNTRUP761_SUPPORT == ENABLED)
   #include "pqc/sntrup761.h"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief KEM context
 **/

typedef struct
{
   const KemAlgo *kemAlgo; ///<Key encapsulation mechanism
   uint8_t *sk;            ///<Secret key
   uint8_t *pk;            ///<Public key
} KemContext;


//KEM related functions
void kemInit(KemContext *context, const KemAlgo *kemAlgo);
void kemFree(KemContext *context);

error_t kemGenerateKeyPair(KemContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t kemLoadPublicKey(KemContext *context, const uint8_t *pk);

error_t kemEncapsulate(KemContext *context, const PrngAlgo *prngAlgo,
   void *prngContext, uint8_t *ct, uint8_t *ss);

error_t kemDecapsulate(KemContext *context, const uint8_t *ct, uint8_t *ss);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
