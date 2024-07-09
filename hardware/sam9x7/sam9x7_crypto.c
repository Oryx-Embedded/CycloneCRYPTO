/**
 * @file sam9x7_crypto.c
 * @brief SAM9X7 hardware cryptographic accelerator
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
#include "sam.h"
#include "core/crypto.h"
#include "hardware/sam9x7/sam9x7_crypto.h"
#include "hardware/sam9x7/sam9x7_crypto_trng.h"
#include "hardware/sam9x7/sam9x7_crypto_hash.h"
#include "hardware/sam9x7/sam9x7_crypto_cipher.h"
#include "debug.h"

//Global variables
OsMutex sam9x7CryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t sam9x7CryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&sam9x7CryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

#if (SAM9X7_CRYPTO_TRNG_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize TRNG module
      error = trngInit();
   }
#endif

#if (SAM9X7_CRYPTO_HASH_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      uint32_t temp;

      //Enable SHA peripheral clock
      PMC_REGS->PMC_PCR = PMC_PCR_PID(ID_SHA);
      temp = PMC_REGS->PMC_PCR;
      PMC_REGS->PMC_PCR = temp | PMC_PCR_CMD_Msk | PMC_PCR_EN_Msk;
   }
#endif

#if (SAM9X7_CRYPTO_CIPHER_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      uint32_t temp;

      //Enable AES peripheral clock
      PMC_REGS->PMC_PCR = PMC_PCR_PID(ID_AES);
      temp = PMC_REGS->PMC_PCR;
      PMC_REGS->PMC_PCR = temp | PMC_PCR_CMD_Msk | PMC_PCR_EN_Msk;

      //Enable TDES peripheral clock
      PMC_REGS->PMC_PCR = PMC_PCR_PID(ID_TDES);
      temp = PMC_REGS->PMC_PCR;
      PMC_REGS->PMC_PCR = temp | PMC_PCR_CMD_Msk | PMC_PCR_EN_Msk;
   }
#endif

   //Return status code
   return error;
}
