/**
 * @file kmac_xof.c
 * @brief KMACXOF (KMAC with arbitrary-length output)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "xof/kmac_xof.h"

//Check crypto library configuration
#if (KMAC_XOF_SUPPORT == ENABLED)

//KMACXOF128 object identifier (2.16.840.1.101.3.4.2.21)
const uint8_t KMAC_XOF128_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x15};
//KMACXOF256 object identifier (2.16.840.1.101.3.4.2.22)
const uint8_t KMAC_XOF256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x16};


/**
 * @brief Digest a message using KMACXOF
 * @param[in] strength Number of bits of security (128 for KMACXOF128 and
 *   256 for KMACXOF256)
 * @param[in] key Pointer to the secret key (K)
 * @param[in] keyLen Length of the secret key
 * @param[in] input Pointer to the input data (X)
 * @param[in] inputLen Length of the input data
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data (L)
 * @return Error code
 **/

error_t kmacXofCompute(uint_t strength, const void *key, size_t keyLen,
   const void *input, size_t inputLen, const char_t *custom, size_t customLen,
   uint8_t *output, size_t outputLen)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   KmacXofContext *context;
#else
   KmacXofContext context[1];
#endif

   //Check parameters
   if(input == NULL && inputLen != 0)
      return ERROR_INVALID_PARAMETER;

   if(output == NULL && outputLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the KMACXOF context
   context = cryptoAllocMem(sizeof(KmacXofContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the KMACXOF context
   error = kmacXofInit(context, strength, key, keyLen, custom, customLen);

   //Check status code
   if(!error)
   {
      //Absorb input data
      kmacXofAbsorb(context, input, inputLen);
      //Finish absorbing phase
      kmacXofFinal(context);
      //Extract data from the squeezing phase
      kmacXofSqueeze(context, output, outputLen);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize KMACXOF context
 * @param[in] context Pointer to the KMACXOF context to initialize
 * @param[in] strength Number of bits of security (128 for KMACXOF128 and
 *   256 for KMACXOF256)
 * @param[in] key Pointer to the secret key (K)
 * @param[in] keyLen Length of the secret key
 * @param[in] custom Customization string (S)
 * @param[in] customLen Length of the customization string
 * @return Error code
 **/

error_t kmacXofInit(KmacXofContext *context, uint_t strength, const void *key,
   size_t keyLen, const char_t *custom, size_t customLen)
{
   error_t error;
   size_t i;
   size_t n;
   size_t rate;
   uint8_t buffer[sizeof(size_t) + 1];

   //Make sure the KMACXOF context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the supplied key is valid
   if(key == NULL && keyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize cSHAKE context
   error = cshakeInit(&context->cshakeContext, strength, "KMAC", 4, custom,
      customLen);
   //Any error to report?
   if(error)
      return error;

   //The rate of the underlying Keccak sponge function is 168 for KMACXOF128
   //and 136 for KMACXOF256
   rate = context->cshakeContext.keccakContext.blockSize;

   //Absorb the string representation of the rate
   cshakeLeftEncode(rate, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);
   i = n;

   //Absorb the string representation of K
   cshakeLeftEncode(keyLen * 8, buffer, &n);
   cshakeAbsorb(&context->cshakeContext, buffer, n);
   cshakeAbsorb(&context->cshakeContext, key, keyLen);
   i += n + keyLen;

   //The padding string consists of bytes set to zero
   buffer[0] = 0;

   //Pad the result with zeros until it is a byte string whose length in
   //bytes is a multiple of the rate
   while((i % rate) != 0)
   {
      //Absorb the padding string
      cshakeAbsorb(&context->cshakeContext, buffer, 1);
      i++;
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the KMACXOF context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void kmacXofAbsorb(KmacXofContext *context, const void *input, size_t length)
{
   //Absorb the input data
   cshakeAbsorb(&context->cshakeContext, input, length);
}


/**
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the KMACXOF context
 **/

void kmacXofFinal(KmacXofContext *context)
{
   uint8_t buffer[2];

   //When used as a XOF, KMAC is computed by setting the encoded output length
   //to 0
   buffer[0] = 0;
   buffer[1] = 1;
   cshakeAbsorb(&context->cshakeContext, buffer, 2);

   //Finish absorbing phase
   cshakeFinal(&context->cshakeContext);
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the KMACXOF context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void kmacXofSqueeze(KmacXofContext *context, uint8_t *output, size_t length)
{
   //Extract data from the squeezing phase
   cshakeSqueeze(&context->cshakeContext, output, length);
}

#endif
