/**
 * @file pic32cz_ca90_crypto.c
 * @brief PIC32CZ CA90 hardware cryptographic accelerator (HSM)
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
 * @version 2.6.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "pic32c.h"
#include "hsm_boot.h"
#include "core/crypto.h"
#include "hardware/pic32cz_ca90/pic32cz_ca90_crypto.h"
#include "hardware/pic32cz_ca90/pic32cz_ca90_crypto_trng.h"
#include "debug.h"

//Global variables
OsMutex pic32czca90CryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t pic32czca90CryptoInit(void)
{
   error_t error;
   int_t status;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&pic32czca90CryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Initialize HSM
   do
   {
      //Load HSM firmware image
      status = Hsm_Boot_Initialization();

      //Check status code
      if(status != 0)
      {
         //Check whether HSM is operational
         status = Hsm_Boot_GetStatus();
      }

      //Check status code
   } while(status == 0);

#if (PIC32CZ_CA90_CRYPTO_TRNG_SUPPORT == ENABLED)
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
