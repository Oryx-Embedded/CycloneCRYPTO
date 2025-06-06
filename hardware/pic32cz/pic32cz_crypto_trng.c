/**
 * @file pic32cz_crypto_trng.c
 * @brief PIC32CZ true random number generator
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
#include "pic32c.h"
#include "core/crypto.h"
#include "hardware/pic32cz/pic32cz_crypto.h"
#include "hardware/pic32cz/pic32cz_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (PIC32CZ_CRYPTO_TRNG_SUPPORT == ENABLED)


/**
 * @brief TRNG module initialization
 * @return Error code
 **/

error_t trngInit(void)
{
#if defined(__PIC32CZ2051CA70064__) || defined(__PIC32CZ2051CA70100__) || \
   defined(__PIC32CZ2051CA70144__)
   //Enable TRNG peripheral clock
   PMC_REGS->PMC_PCER1 = (1U << (ID_TRNG - 32));
   //Enable TRNG
   TRNG_REGS->TRNG_CR = TRNG_CR_KEY_PASSWD | TRNG_CR_ENABLE_Msk;
#else
   //Enable TRNG bus clock (CLK_TRNG_APB)
   MCLK_REGS->MCLK_CLKMSK[TRNG_MCLK_ID_APB / 32]  |= (1U << (TRNG_MCLK_ID_APB % 32));
   //Enable TRNG
   TRNG_REGS->TRNG_CTRLA |= TRNG_CTRLA_ENABLE_Msk;
#endif

   //Successful initialization
   return NO_ERROR;
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

   //Initialize variable
   value = 0;

   //Acquire exclusive access to the TRNG module
   osAcquireMutex(&pic32czCryptoMutex);

   //Generate random data
   for(i = 0; i < length; i++)
   {
      //Generate a new 32-bit random value when necessary
      if((i % 4) == 0)
      {
#if defined(__PIC32CZ2051CA70064__) || defined(__PIC32CZ2051CA70100__) || \
   defined(__PIC32CZ2051CA70144__)
         //Wait for the TRNG to contain a valid data
         while((TRNG_REGS->TRNG_ISR & TRNG_ISR_DATRDY_Msk) == 0)
         {
         }

         //Get the 32-bit random value
         value = TRNG_REGS->TRNG_ODATA;
#else
         //Wait for the TRNG to contain a valid data
         while((TRNG_REGS->TRNG_INTFLAG & TRNG_INTFLAG_DATARDY_Msk) == 0)
         {
         }

         //Get the 32-bit random value
         value = TRNG_REGS->TRNG_DATA;
#endif
      }

      //Copy random byte
      data[i] = value & 0xFF;
      //Shift the 32-bit random value
      value >>= 8;
   }

   //Release exclusive access to the TRNG module
   osReleaseMutex(&pic32czCryptoMutex);

   //Successful processing
   return NO_ERROR;
}

#endif
