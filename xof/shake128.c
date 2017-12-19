/**
 * @file shake128.c
 * @brief SHAKE128 extendable-output function (XOF)
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
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
 * @section Description
 *
 * SHAKE128 is a function on binary data in which the output can be extended
 * to any desired length. SHAKE128 supports 128 bits of security strength.
 * Refer to FIPS 202 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "xof/shake128.h"

//Check crypto library configuration
#if (SHAKE128_SUPPORT == ENABLED)

//SHAKE128 object identifier (2.16.840.1.101.3.4.2.11)
const uint8_t shake128Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B};


/**
 * @brief Digest a message using SHAKE128
 * @param[in] input Pointer to the input data
 * @param[in] inputLen Length of the input data
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data
 * @return Error code
 **/

error_t shake128Compute(const void *input, size_t inputLen,
   uint8_t *output, size_t outputLen)
{
   Shake128Context *context;

   //Allocate a memory buffer to hold the SHAKE128 context
   context = cryptoAllocMem(sizeof(Shake128Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Initialize the SHAKE128 context
   shake128Init(context);
   //Absorb input data
   shake128Absorb(context, input, inputLen);
   //Finish absorbing phase
   shake128Final(context);
   //Extract data from the squeezing phase
   shake128Squeeze(context, output, outputLen);

   //Free previously allocated memory
   cryptoFreeMem(context);
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SHAKE128 context
 * @param[in] context Pointer to the SHAKE128 context to initialize
 **/

void shake128Init(Shake128Context *context)
{
   //SHAKE128 supports 128 bits of security strength
   keccakInit(context, 2 * 128);
}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the SHAKE128 context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void shake128Absorb(Shake128Context *context, const void *input, size_t length)
{
   //Absorb the input data
   keccakAbsorb(context, input, length);
}


/**
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the SHAKE128 context
 **/

void shake128Final(Shake128Context *context)
{
   //Finish absorbing phase (padding byte is 0x1F for XOFs)
   keccakFinal(context, KECCAK_XOF_PAD);
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the SHAKE128 context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void shake128Squeeze(Shake128Context *context, uint8_t *output, size_t length)
{
   //Extract data from the squeezing phase
   keccakSqueeze(context, output, length);
}

#endif
