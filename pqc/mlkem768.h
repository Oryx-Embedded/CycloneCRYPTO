/**
 * @file mlkem768.h
 * @brief ML-KEM-768 key encapsulation mechanism
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

#ifndef _MLKEM768_H
#define _MLKEM768_H

//Dependencies
#include "core/crypto.h"

//Public key length
#define MLKEM768_PUBLIC_KEY_LEN 1184
//Secret key length
#define MLKEM768_SECRET_KEY_LEN 2400
//Ciphertext length
#define MLKEM768_CIPHERTEXT_LEN 1088
//Shared secret length
#define MLKEM768_SHARED_SECRET_LEN 32

//Common interface for key encapsulation mechanisms (KEM)
#define MLKEM768_KEM_ALGO (&mlkem768KemAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ML-KEM-768 related constants
extern const KemAlgo mlkem768KemAlgo;

//ML-KEM-768 related functions
error_t mlkem768GenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *pk, uint8_t *sk);

error_t mlkem768Encapsulate(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *ct, uint8_t *ss, const uint8_t *pk);

error_t mlkem768Decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
