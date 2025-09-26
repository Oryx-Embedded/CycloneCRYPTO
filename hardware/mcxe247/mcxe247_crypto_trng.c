/**
 * @file mcxe247_crypto_trng.c
 * @brief NXP MCX E247 true random number generator
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
#include "core/crypto.h"
#include "hardware/mcxe247/mcxe247_crypto.h"
#include "hardware/mcxe247/mcxe247_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (MCXE247_CRYPTO_TRNG_SUPPORT == ENABLED)

//Global variables
static uint8_t buffer[16];
static size_t bufferPos;


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
   uint32_t status;

   //Mark the buffer as empty
   bufferPos = sizeof(buffer);

   //Check for the previous CSEC command to complete
   while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
   {
   }

   //Clear error flags
   FTFC->FSTAT = FTFC_FSTAT_FPVIOL_MASK | FTFC_FSTAT_ACCERR_MASK;

   //Start CSEC command
   ELA_CSEC->DATA_32[0] = CSEC_CMD_INIT_RNG;

   //Wait for the CSEC command to complete
   while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
   {
   }

   //Retrieve status code
   status = ELA_CSEC->DATA_32[1] >> 16;

   //Return status code
   return (status == CSEC_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   size_t i;
   uint32_t temp;
   uint32_t status;

   //Initialize status code
   status = CSEC_ERC_NO_ERROR;

   //Acquire exclusive access to the CSEC module
   osAcquireMutex(&mcxe247CryptoMutex);

   //Generate random data
   for(i = 0; i < length && status == CSEC_ERC_NO_ERROR; i++)
   {
      //Generate a new 128-bit random value when necessary
      if(bufferPos >= sizeof(buffer))
      {
         //Check for the previous CSEC command to complete
         while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
         {
         }

         //Clear error flags
         FTFC->FSTAT = FTFC_FSTAT_FPVIOL_MASK | FTFC_FSTAT_ACCERR_MASK;

         //Start CSEC command
         ELA_CSEC->DATA_32[0] = CSEC_CMD_RND;

         //Wait for the CSEC command to complete
         while((FTFC->FSTAT & FTFC_FSTAT_CCIF_MASK) == 0)
         {
         }

         //Retrieve status code
         status = ELA_CSEC->DATA_32[1] >> 16;

         //Check status code
         if(status == CSEC_ERC_NO_ERROR)
         {
            //Save the 128-bit random value
            temp = ELA_CSEC->DATA_32[4];
            STORE32BE(temp, buffer);
            temp = ELA_CSEC->DATA_32[5];
            STORE32BE(temp, buffer + 4);
            temp = ELA_CSEC->DATA_32[6];
            STORE32BE(temp, buffer + 8);
            temp = ELA_CSEC->DATA_32[7];
            STORE32BE(temp, buffer + 12);
         }

         //Rewind to the beginning of the buffer
         bufferPos = 0;
      }

      //Extract a random byte
      data[i] = buffer[bufferPos++];
   }

   //Release exclusive access to the CSEC module
   osReleaseMutex(&mcxe247CryptoMutex);

   //Return status code
   return (status == CSEC_ERC_NO_ERROR) ? NO_ERROR : ERROR_FAILURE;
}

#endif
