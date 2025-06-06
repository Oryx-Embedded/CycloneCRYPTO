/**
 * @file mlkem768.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pqc/mlkem768.h"

//Check crypto library configuration
#if (MLKEM768_SUPPORT == ENABLED)

//Dependencies (liboqs)
#include <oqs/oqs.h>

//Common interface for key encapsulation mechanisms (KEM)
const KemAlgo mlkem768KemAlgo =
{
   "ML-KEM-768",
   MLKEM768_PUBLIC_KEY_LEN,
   MLKEM768_SECRET_KEY_LEN,
   MLKEM768_CIPHERTEXT_LEN,
   MLKEM768_SHARED_SECRET_LEN,
   (KemAlgoGenerateKeyPair) mlkem768GenerateKeyPair,
   (KemAlgoEncapsulate) mlkem768Encapsulate,
   (KemAlgoDecapsulate) mlkem768Decapsulate
};


/**
 * @brief Key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[out] pk Public key
 * @param[out] sk Secret key
 * @return Error code
 **/

error_t mlkem768GenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *pk, uint8_t *sk)
{
   OQS_STATUS status;

   //Key pair generation
   status = OQS_KEM_ml_kem_768_keypair(pk, sk);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Encapsulation algorithm
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[out] ct Ciphertext
 * @param[out] ss Shared secret
 * @param[in] pk Public key
 * @return Error code
 **/

error_t mlkem768Encapsulate(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
   OQS_STATUS status;

   //Encapsulation algorithm
   status = OQS_KEM_ml_kem_768_encaps(ct, ss, pk);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Decapsulation algorithm
 * @param[out] ss Shared secret
 * @param[in] ct Ciphertext
 * @param[in] sk Secret key
 * @return Error code
 **/

error_t mlkem768Decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
   OQS_STATUS status;

   //Decapsulation algorithm
   status = OQS_KEM_ml_kem_768_decaps(ss, ct, sk);

   //Return status code
   return (status == OQS_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
