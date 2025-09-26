/**
 * @file mcxn947_crypto_trng.c
 * @brief NXP MCX N947 true random number generator
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
#include <mcuxClEls.h>
#include <internal/mcuxClTrng_Internal.h>
#include "core/crypto.h"
#include "hardware/mcxn947/mcxn947_crypto.h"
#include "hardware/mcxn947/mcxn947_crypto_trng.h"
#include "debug.h"

//Global variables
static uint32_t buffer[MCUXCLTRNG_ELS_TRNG_OUTPUT_SIZE / 4];
static size_t bufferPos;

//Check crypto library configuration
#if (MCXN947_CRYPTO_TRNG_SUPPORT == ENABLED)


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Mark the buffer as empty
   bufferPos = MCUXCLTRNG_ELS_TRNG_OUTPUT_SIZE;

   //Initialize TRNG
   MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClTrng_Init());

   //Check the protection token and the return value
   if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_Init) ||
      status != MCUXCLTRNG_STATUS_OK)
   {
      error = ERROR_FAILURE;
   }

   //End of function call
   MCUX_CSSL_FP_FUNCTION_CALL_END();

   //Return status code
   return error;
}


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   error_t error;
   size_t i;
   uint32_t temp;

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the ELS module
   osAcquireMutex(&mcxn947CryptoMutex);

   //Generate random data
   for(i = 0; i < length && !error; i++)
   {
      //Generate a new 32-byte random value when necessary
      if(bufferPos >= MCUXCLTRNG_ELS_TRNG_OUTPUT_SIZE)
      {
         //Generate random bytes
         MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClTrng_getEntropyInput(
            &elsSession, buffer, MCUXCLTRNG_ELS_TRNG_OUTPUT_SIZE));

         //Check the protection token and the return value
         if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_getEntropyInput) ||
            status != MCUXCLTRNG_STATUS_OK)
         {
            error = ERROR_FAILURE;
         }

         //End of function call
         MCUX_CSSL_FP_FUNCTION_CALL_END();

         //Rewind to the beginning of the buffer
         bufferPos = 0;
      }

      //Extract a random byte
      data[i] = (buffer[bufferPos / 4] >> ((bufferPos % 4) * 8)) & 0xFF;
      //Increment index
      bufferPos++;
   }

   //Release exclusive access to the ELS module
   osReleaseMutex(&mcxn947CryptoMutex);

   //Return status code
   return error;
}

#endif
