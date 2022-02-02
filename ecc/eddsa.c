/**
 * @file eddsa.c
 * @brief EdDSA (Edwards-Curve Digital Signature Algorithm)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.1.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "ecc/eddsa.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)


/**
 * @brief Initialize an EdDSA public key
 * @param[in] key Pointer to the EdDSA public key to initialize
 **/

void eddsaInitPublicKey(EddsaPublicKey *key)
{
   //Initialize multiple precision integer
   mpiInit(&key->q);
}


/**
 * @brief Release an EdDSA public key
 * @param[in] key Pointer to the EdDSA public key to free
 **/

void eddsaFreePublicKey(EddsaPublicKey *key)
{
   //Free multiple precision integer
   mpiFree(&key->q);
}


/**
 * @brief Initialize an EdDSA private key
 * @param[in] key Pointer to the EdDSA private key to initialize
 **/

void eddsaInitPrivateKey(EddsaPrivateKey *key)
{
   //Initialize multiple precision integers
   mpiInit(&key->d);
   mpiInit(&key->q);

   //Initialize private key slot
   key->slot = -1;
}


/**
 * @brief Release an EdDSA private key
 * @param[in] key Pointer to the EdDSA public key to free
 **/

void eddsaFreePrivateKey(EddsaPrivateKey *key)
{
   //Free multiple precision integers
   mpiFree(&key->d);
   mpiFree(&key->q);
}

#endif
