/**
 * @file camellia.h
 * @brief Camellia encryption algorithm
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.7.6
 **/

#ifndef _CAMELLIA_H
#define _CAMELLIA_H

//Dependencies
#include "crypto.h"

//Camellia block size
#define CAMELLIA_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define CAMELLIA_CIPHER_ALGO (&camelliaCipherAlgo)


/**
 * @brief Structure describing subkey generation
 **/

typedef struct
{
   uint8_t index;
   uint8_t key;
   uint8_t shift;
   uint8_t position;
} CamelliaSubkey;


/**
 * @brief Camellia algorithm context
 **/

typedef struct
{
   uint_t nr;
   uint32_t k[16];
   uint32_t ks[68];
} CamelliaContext;


//Camellia related constants
extern const CipherAlgo camelliaCipherAlgo;

//Camellia related functions
error_t camelliaInit(CamelliaContext *context, const uint8_t *key, size_t keyLength);
void camelliaEncryptBlock(CamelliaContext *context, const uint8_t *input, uint8_t *output);
void camelliaDecryptBlock(CamelliaContext *context, const uint8_t *input, uint8_t *output);

#endif
