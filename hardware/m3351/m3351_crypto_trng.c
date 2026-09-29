/**
 * @file m3351_crypto_trng.c
 * @brief M3351 true random number generator
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "NuMicro.h"
#include "core/crypto.h"
#include "hardware/m3351/m3351_crypto.h"
#include "hardware/m3351/m3351_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (M3351_CRYPTO_TRNG_SUPPORT == ENABLED)


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
   int32_t status;

   //Enable TRNG clock
   CLK_EnableModuleClock(TRNG_MODULE);

   //Initialize TRNG module
   status = TRNG_Open();

   //Return status code
   return (status == 0) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   size_t i;
   int32_t status;
   uint32_t value;

   //Initialize variables
   status = 0;
   value = 0;

   //Acquire exclusive access to the TRNG module
   osAcquireMutex(&m3351CryptoMutex);

   //Generate random data
   for(i = 0; i < length; i++)
   {
      //Generate a new 32-bit random value when necessary
      if((i % 4) == 0)
      {
         //Get 32-bit random value
         status = TRNG_GenWord(&value);
         //Check status code
         if(status != 0)
         {
            break;
         }
      }

      //Copy random byte
      data[i] = value & 0xFF;
      //Shift the 32-bit random value
      value >>= 8;
   }

   //Release exclusive access to the TRNG module
   osReleaseMutex(&m3351CryptoMutex);

   //Return status code
   return (status == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
