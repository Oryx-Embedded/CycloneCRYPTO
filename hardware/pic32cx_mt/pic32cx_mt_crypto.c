/**
 * @file pic32cx_mt_crypto.c
 * @brief PIC32CX MTC/MTG/MTSH hardware cryptographic accelerator
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
#include "hardware/pic32cx_mt/pic32cx_mt_crypto.h"
#include "hardware/pic32cx_mt/pic32cx_mt_crypto_trng.h"
#include "hardware/pic32cx_mt/pic32cx_mt_crypto_hash.h"
#include "hardware/pic32cx_mt/pic32cx_mt_crypto_cipher.h"
#include "hardware/pic32cx_mt/pic32cx_mt_crypto_pkc.h"
#include "debug.h"

//Global variables
OsMutex pic32cxmtCryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t pic32cxmtCryptoInit(void)
{
   error_t error;
#if (PIC32CX_MT_CRYPTO_HASH_SUPPORT == ENABLED || PIC32CX_MT_CRYPTO_CIPHER_SUPPORT == ENABLED)
   uint32_t temp;
#endif

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&pic32cxmtCryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

#if (PIC32CX_MT_CRYPTO_TRNG_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize TRNG module
      error = trngInit();
   }
#endif

#if (PIC32CX_MT_CRYPTO_HASH_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Enable SHA peripheral clock
      PMC_REGS->PMC_PCR = PMC_PCR_PID(ID_SHA);
      temp = PMC_REGS->PMC_PCR;
      PMC_REGS->PMC_PCR = temp | PMC_PCR_CMD_Msk | PMC_PCR_EN_Msk;
   }
#endif

#if (PIC32CX_MT_CRYPTO_CIPHER_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Enable AES peripheral clock
      PMC_REGS->PMC_PCR = PMC_PCR_PID(ID_AES);
      temp = PMC_REGS->PMC_PCR;
      PMC_REGS->PMC_PCR = temp | PMC_PCR_CMD_Msk | PMC_PCR_EN_Msk;
   }
#endif

#if (PIC32CX_MT_CRYPTO_PKC_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize public key accelerator
      error = cpkccInit();
   }
#endif

   //Return status code
   return error;
}
