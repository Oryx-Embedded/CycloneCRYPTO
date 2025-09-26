/**
 * @file mimxrt1180_crypto.c
 * @brief i.MX RT1180 hardware cryptographic accelerator (ELE)
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
#include "ele_fw.h"
#include "core/crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto_trng.h"
#include "debug.h"

//Global variables
OsMutex mimxrt1180CryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t mimxrt1180CryptoInit(void)
{
   error_t error;
   uint32_t version;
   status_t status;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&mimxrt1180CryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Loading ELE firmware...\r\n");

      //Load ELE firmware
      status = ELE_LoadFw(MU_APPS_S3MUA, ele_fw);

      //Check status code
      if(status == kStatus_Success)
      {
         //Retrieve ELE firmware version
         status = ELE_GetFwVersion(MU_APPS_S3MUA, &version);
      }

      //Check status code
      if(status == kStatus_Success)
      {
         //Dump firmware version
         TRACE_INFO("ELE firmware version: 0x%08X\r\n", version);

         //Successful initialization
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }
   }

#if (MIMXRT1180_CRYPTO_TRNG_SUPPORT == ENABLED)
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
