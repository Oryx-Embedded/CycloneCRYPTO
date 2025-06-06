/**
 * @file gd32f2xx_crypto_hash.c
 * @brief GD32F2 hash hardware accelerator
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
#include "gd32f20x.h"
#include "gd32f20x_hau.h"
#include "core/crypto.h"
#include "hardware/gd32f2xx/gd32f2xx_crypto.h"
#include "hardware/gd32f2xx/gd32f2xx_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (GD32F2XX_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief HAU module initialization
 * @return Error code
 **/

error_t hauInit(void)
{
   //Enable HAU peripheral clock
   rcu_periph_clock_enable(RCU_HAU);

   //Successful processing
   return NO_ERROR;
}


#if (MD5_SUPPORT == ENABLED)

/**
 * @brief Digest a message using MD5
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t md5Compute(const void *data, size_t length, uint8_t *digest)
{
   ErrStatus status;

   //Acquire exclusive access to the HAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Digest the message using MD5
   status = hau_hash_md5((uint8_t *) data, length, digest);
   //Release exclusive access to the HAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (SHA1_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-1
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha1Compute(const void *data, size_t length, uint8_t *digest)
{
   ErrStatus status;

   //Acquire exclusive access to the HAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Digest the message using SHA-1
   status = hau_hash_sha_1((uint8_t *) data, length, digest);
   //Release exclusive access to the HAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (SHA224_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-224
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha224Compute(const void *data, size_t length, uint8_t *digest)
{
   ErrStatus status;

   //Acquire exclusive access to the HAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Digest the message using SHA-224
   status = hau_hash_sha_224((uint8_t *) data, length, digest);
   //Release exclusive access to the HAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
   ErrStatus status;

   //Acquire exclusive access to the HAU module
   osAcquireMutex(&gd32f2xxCryptoMutex);
   //Digest the message using SHA-256
   status = hau_hash_sha_256((uint8_t *) data, length, digest);
   //Release exclusive access to the HAU module
   osReleaseMutex(&gd32f2xxCryptoMutex);

   //Return status code
   return (status == SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
#endif
