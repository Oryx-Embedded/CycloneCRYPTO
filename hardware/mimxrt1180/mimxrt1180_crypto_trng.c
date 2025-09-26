/**
 * @file mimxrt1180_crypto_trng.c
 * @brief i.MX RT1180 true random number generator
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
 * @version 2.5.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "fsl_device_registers.h"
#include "ele_crypto.h"
#include "core/crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1180_CRYPTO_TRNG_SUPPORT == ENABLED)


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
   status_t status;
   uint32_t state;

   //Initialize TRNG context
   status = ELE_StartRng(MU_APPS_S3MUA);

   //Check status code
   if(status == kStatus_Success)
   {
      //Wait for the TRNG to be ready for use
      do
      {
         //Get TRNG state
         status = ELE_GetTrngState(MU_APPS_S3MUA, &state);

         //Check TRNG state
      } while(status == kStatus_Success && (state & 0xFF) != kELE_TRNG_ready);
   }

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   size_t i;
   uint32_t value;
   status_t status;

   //Initialize status code
   status = kStatus_Success;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Generate random data
   for(i = 0; i < length; i++)
   {
      //Generate a new 32-bit random value when necessary
      if((i % 4) == 0)
      {
         //Get 32-bit random value
         status = ELE_RngGetRandom(MU_APPS_S3MUA, &value, 4, kNoReseed);
         //Check status code
         if(status != kStatus_Success)
         {
            break;
         }
      }

      //Copy random byte
      data[i] = value & 0xFF;
      //Shift the 32-bit random value
      value >>= 8;
   }

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}

#endif
