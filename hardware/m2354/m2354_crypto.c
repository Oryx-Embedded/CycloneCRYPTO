/**
 * @file m2354_crypto.c
 * @brief M2354 hardware cryptographic accelerator
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
#include "m2354.h"
#include "core/crypto.h"
#include "hardware/m2354/m2354_crypto.h"
#include "hardware/m2354/m2354_crypto_trng.h"
#include "debug.h"

//Global variables
OsMutex m2354CryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t m2354CryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Enable CRPT clock
   CLK_EnableModuleClock(CRPT_MODULE);

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&m2354CryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

#if (M2354_CRYPTO_TRNG_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize TRNG module
      error = trngInit();
   }
#endif

   //Return status code
   return error;
}
