/**
 * @file lpc55s6x_crypto.c
 * @brief LPC55S6x hardware cryptographic accelerator
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "fsl_device_registers.h"
#include "fsl_hashcrypt.h"
#include "fsl_casper.h"
#include "core/crypto.h"
#include "hardware/lpc55s6x/lpc55s6x_crypto.h"
#include "hardware/lpc55s6x/lpc55s6x_crypto_trng.h"
#include "hardware/lpc55s6x/lpc55s6x_crypto_hash.h"
#include "hardware/lpc55s6x/lpc55s6x_crypto_cipher.h"
#include "hardware/lpc55s6x/lpc55s6x_crypto_pkc.h"
#include "debug.h"

//Global variables
OsMutex lpc55s6xCryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t lpc55s6xCryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&lpc55s6xCryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

#if (LPC55S6X_CRYPTO_TRNG_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize TRNG module
      error = trngInit();
   }
#endif

#if (LPC55S6X_CRYPTO_HASH_SUPPORT == ENABLED || \
   LPC55S6X_CRYPTO_CIPHER_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize HASHCRYPT peripheral
      HASHCRYPT_Init(HASHCRYPT);
   }
#endif

#if (LPC55S6X_CRYPTO_PKC_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize CASPER peripheral
      CASPER_Init(CASPER);
   }
#endif

   //Return status code
   return error;
}
