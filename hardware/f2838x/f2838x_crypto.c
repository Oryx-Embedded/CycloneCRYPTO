/**
 * @file f2838x_crypto.c
 * @brief TMS320F2838xD hardware cryptographic accelerator
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
#include <stdint.h>
#include <stdbool.h>
#include "driverlib_cm/sysctl.h"
#include "core/crypto.h"
#include "hardware/f2838x/f2838x_crypto.h"
#include "debug.h"

//Global variables
OsMutex f2838xCryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t f2838xCryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Enable AES peripheral clock
   SysCtl_enablePeripheral(SYSCTL_PERIPH_CLK_AESIP);
   //Reset AES peripheral
   SysCtl_resetPeripheral(SYSCTL_PERIPH_RES_AESIP);

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&f2838xCryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Return status code
   return error;
}
