/**
 * @file same54_crypto.c
 * @brief SAME54 hardware cryptography accelerator
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2019 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.9.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "same54.h"
#include "pukcc/CryptoLib_typedef_pb.h"
#include "pukcc/CryptoLib_Headers_pb.h"
#include "core/crypto.h"
#include "hardware/same54_crypto.h"
#include "hardware/same54_crypto_pukcc.h"
#include "debug.h"

//Global variables
OsMutex same54CryptoMutex;


/**
 * @brief Cryptography accelerator initialization
 **/

error_t same54CryptoInit(void)
{
   error_t error;

   //Create a mutex to prevent simultaneous access to the cryptography
   //accelerator
   if(!osCreateMutex(&same54CryptoMutex))
   {
      //Failed to create mutex
      return ERROR_OUT_OF_RESOURCES;
   }

   //Enable TRNG peripheral clock
   MCLK->APBCMASK.reg |= MCLK_APBCMASK_TRNG;
   //Enable TRNG
   TRNG->CTRLA.reg |= TRNG_CTRLA_ENABLE;

   //Initialize public key accelerator
   error = pukccInit();

   //Return status code
   return error;
}
