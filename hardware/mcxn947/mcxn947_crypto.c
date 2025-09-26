/**
 * @file mcxn947_crypto.c
 * @brief NXP MCX N947 hardware cryptographic accelerator
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
#include <ip_platform.h>
#include <mcuxClEls.h>
#include <mcuxClSession.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClRsa.h>
#include <mcuxClEcc.h>
#include "core/crypto.h"
#include "hardware/mcxn947/mcxn947_crypto.h"
#include "hardware/mcxn947/mcxn947_crypto_trng.h"
#include "debug.h"

//Maximum cpuWA usage
#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLRSA_VERIFY_NOVERIFY_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLRSA_SIGN_PLAIN_NOENCODE_4096_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLRSA_SIGN_CRT_NOENCODE_4096_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_POINTMULT_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_SIGN_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_VERIFY_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WACPU_SIZE, \
   MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WACPU_SIZE))))))))))))

//Maximum pkcWA usage
#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLRSA_VERIFY_4096_WAPKC_SIZE, \
   MCUXCLCORE_MAX(MCUXCLRSA_SIGN_PLAIN_4096_WAPKC_SIZE, \
   MCUXCLCORE_MAX(MCUXCLRSA_SIGN_CRT_4096_WAPKC_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_POINTMULT_WAPKC_SIZE_640, \
   MCUXCLCORE_MAX(MCUXCLECC_SIGN_WAPKC_SIZE_640, \
   MCUXCLCORE_MAX(MCUXCLECC_VERIFY_WAPKC_SIZE_640, \
   MCUXCLCORE_MAX(MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WAPKC_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WAPKC_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WAPKC_SIZE, \
   MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WAPKC_SIZE, \
   MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WAPKC_SIZE))))))))))

//Global variables
OsMutex mcxn947CryptoMutex;
mcuxClSession_Descriptor_t elsSession;

//cpuWA buffer
static uint32_t cpuWaBuffer[MAX_CPUWA_SIZE / 4];


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t mcxn947CryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&mcxn947CryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Check status code
   if(!error)
   {
      //Enable ELS module
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Enable_Async());

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Enable_Async) ||
         status != MCUXCLELS_STATUS_OK_WAIT)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Wait for the operation to complete
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_WaitForOperation(
         MCUXCLELS_ERROR_FLAGS_CLEAR));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) ||
         status != MCUXCLELS_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Reset ELS module
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_Reset_Async(
         MCUXCLELS_RESET_DO_NOT_CANCEL));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Reset_Async) ||
         status != MCUXCLELS_STATUS_OK_WAIT)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Wait for the operation to complete
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClEls_WaitForOperation(
         MCUXCLELS_ERROR_FLAGS_CLEAR));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) ||
         status != MCUXCLELS_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Allocate and initialize session with pkcWA on the beginning of PKC RAM
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClSession_init(
         &elsSession, cpuWaBuffer, MAX_CPUWA_SIZE, (uint32_t *) PKC_RAM_ADDR,
         MAX_PKCWA_SIZE));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) ||
         status != MCUXCLSESSION_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Initialize RNG context
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClRandom_init(
         &elsSession, NULL, mcuxClRandomModes_Mode_ELS_Drbg));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) ||
         status != MCUXCLRANDOM_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

   //Check status code
   if(!error)
   {
      //Initialize PRNG
      MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status, token, mcuxClRandom_ncInit(&elsSession));

      //Check the protection token and the return value
      if(token != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) ||
         status != MCUXCLRANDOM_STATUS_OK)
      {
         error = ERROR_FAILURE;
      }

      //End of function call
      MCUX_CSSL_FP_FUNCTION_CALL_END();
   }

#if (MCXN947_CRYPTO_TRNG_SUPPORT == ENABLED)
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
