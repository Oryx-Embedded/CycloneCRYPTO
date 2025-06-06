/**
 * @file m480_crypto_hash.c
 * @brief M480 hash hardware accelerator
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
#include "m480.h"
#include "core/crypto.h"
#include "hardware/m480/m480_crypto.h"
#include "hardware/m480/m480_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (M480_CRYPTO_HASH_SUPPORT == ENABLED)


/**
 * @brief Update hash value
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 **/

void hashProcessData(const uint8_t *data, size_t length)
{
   size_t i;

   //Process input data
   for(i = 0; i < length; i += 4)
   {
      //Wait for the DATINREQ bit to be set
      while((CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk) == 0)
      {
      }

      //Write one word of data
      CRPT->HMAC_DATIN = __UNALIGNED_UINT32_READ(data + i);
   }

   //Wait for the processing to complete
   while((CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk) == 0)
   {
   }
}


#if (SHA1_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-1
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha1Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t temp;
   uint8_t buffer[64];

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m480CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Select the relevant hash algorithm
   CRPT->HMAC_CTL = CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk |
      CRPT_HMAC_CTL_OPMODE_SHA1;

   //Start SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessData(data, 64);
      //Advance the data pointer
      data = (uint8_t *) data + 64;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 64);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(n >= 56)
   {
      hashProcessData(buffer, 64);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessData(buffer, 64);

   //Save the resulting hash value
   temp = CRPT->HMAC_DGST[0];
   __UNALIGNED_UINT32_WRITE(digest, temp);
   temp = CRPT->HMAC_DGST[1];
   __UNALIGNED_UINT32_WRITE(digest + 4, temp);
   temp = CRPT->HMAC_DGST[2];
   __UNALIGNED_UINT32_WRITE(digest + 8, temp);
   temp = CRPT->HMAC_DGST[3];
   __UNALIGNED_UINT32_WRITE(digest + 12, temp);
   temp = CRPT->HMAC_DGST[4];
   __UNALIGNED_UINT32_WRITE(digest + 16, temp);

   //Stop SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m480CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA224_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-224
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha224Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t temp;
   uint8_t buffer[64];

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m480CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Select the relevant hash algorithm
   CRPT->HMAC_CTL = CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk |
      CRPT_HMAC_CTL_OPMODE_SHA224;

   //Start SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessData(data, 64);
      //Advance the data pointer
      data = (uint8_t *) data + 64;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 64);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(n >= 56)
   {
      hashProcessData(buffer, 64);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessData(buffer, 64);

   //Save the resulting hash value
   temp = CRPT->HMAC_DGST[0];
   __UNALIGNED_UINT32_WRITE(digest, temp);
   temp = CRPT->HMAC_DGST[1];
   __UNALIGNED_UINT32_WRITE(digest + 4, temp);
   temp = CRPT->HMAC_DGST[2];
   __UNALIGNED_UINT32_WRITE(digest + 8, temp);
   temp = CRPT->HMAC_DGST[3];
   __UNALIGNED_UINT32_WRITE(digest + 12, temp);
   temp = CRPT->HMAC_DGST[4];
   __UNALIGNED_UINT32_WRITE(digest + 16, temp);
   temp = CRPT->HMAC_DGST[5];
   __UNALIGNED_UINT32_WRITE(digest + 20, temp);
   temp = CRPT->HMAC_DGST[6];
   __UNALIGNED_UINT32_WRITE(digest + 24, temp);

   //Stop SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m480CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t temp;
   uint8_t buffer[64];

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m480CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Select the relevant hash algorithm
   CRPT->HMAC_CTL = CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk |
      CRPT_HMAC_CTL_OPMODE_SHA256;

   //Start SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

   //Digest the message
   for(n = length; n >= 64; n -= 64)
   {
      //Update hash value
      hashProcessData(data, 64);
      //Advance the data pointer
      data = (uint8_t *) data + 64;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 64);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(n >= 56)
   {
      hashProcessData(buffer, 64);
      osMemset(buffer, 0, 64);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 56);

   //Process the final block
   hashProcessData(buffer, 64);

   //Save the resulting hash value
   temp = CRPT->HMAC_DGST[0];
   __UNALIGNED_UINT32_WRITE(digest, temp);
   temp = CRPT->HMAC_DGST[1];
   __UNALIGNED_UINT32_WRITE(digest + 4, temp);
   temp = CRPT->HMAC_DGST[2];
   __UNALIGNED_UINT32_WRITE(digest + 8, temp);
   temp = CRPT->HMAC_DGST[3];
   __UNALIGNED_UINT32_WRITE(digest + 12, temp);
   temp = CRPT->HMAC_DGST[4];
   __UNALIGNED_UINT32_WRITE(digest + 16, temp);
   temp = CRPT->HMAC_DGST[5];
   __UNALIGNED_UINT32_WRITE(digest + 20, temp);
   temp = CRPT->HMAC_DGST[6];
   __UNALIGNED_UINT32_WRITE(digest + 24, temp);
   temp = CRPT->HMAC_DGST[7];
   __UNALIGNED_UINT32_WRITE(digest + 28, temp);

   //Stop SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m480CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA384_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-384
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha384Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t temp;
   uint8_t buffer[128];

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m480CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Select the relevant hash algorithm
   CRPT->HMAC_CTL = CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk |
      CRPT_HMAC_CTL_OPMODE_SHA384;

   //Start SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

   //Digest the message
   for(n = length; n >= 128; n -= 128)
   {
      //Update hash value
      hashProcessData(data, 128);
      //Advance the data pointer
      data = (uint8_t *) data + 128;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 128);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 112 modulo 128
   if(n >= 112)
   {
      hashProcessData(buffer, 128);
      osMemset(buffer, 0, 128);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 120);

   //Process the final block
   hashProcessData(buffer, 128);

   //Save the resulting hash value
   temp = CRPT->HMAC_DGST[0];
   __UNALIGNED_UINT32_WRITE(digest, temp);
   temp = CRPT->HMAC_DGST[1];
   __UNALIGNED_UINT32_WRITE(digest + 4, temp);
   temp = CRPT->HMAC_DGST[2];
   __UNALIGNED_UINT32_WRITE(digest + 8, temp);
   temp = CRPT->HMAC_DGST[3];
   __UNALIGNED_UINT32_WRITE(digest + 12, temp);
   temp = CRPT->HMAC_DGST[4];
   __UNALIGNED_UINT32_WRITE(digest + 16, temp);
   temp = CRPT->HMAC_DGST[5];
   __UNALIGNED_UINT32_WRITE(digest + 20, temp);
   temp = CRPT->HMAC_DGST[6];
   __UNALIGNED_UINT32_WRITE(digest + 24, temp);
   temp = CRPT->HMAC_DGST[7];
   __UNALIGNED_UINT32_WRITE(digest + 28, temp);
   temp = CRPT->HMAC_DGST[8];
   __UNALIGNED_UINT32_WRITE(digest + 32, temp);
   temp = CRPT->HMAC_DGST[9];
   __UNALIGNED_UINT32_WRITE(digest + 36, temp);
   temp = CRPT->HMAC_DGST[10];
   __UNALIGNED_UINT32_WRITE(digest + 40, temp);
   temp = CRPT->HMAC_DGST[11];
   __UNALIGNED_UINT32_WRITE(digest + 44, temp);

   //Stop SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m480CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#if (SHA512_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-512
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha512Compute(const void *data, size_t length, uint8_t *digest)
{
   size_t n;
   uint32_t temp;
   uint8_t buffer[128];

   //Acquire exclusive access to the CRYPTO module
   osAcquireMutex(&m480CryptoMutex);

   //Reset CRYPTO controller
   SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
   SYS->IPRST0 &= ~SYS_IPRST0_CRPTRST_Msk;

   //Select the relevant hash algorithm
   CRPT->HMAC_CTL = CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk |
      CRPT_HMAC_CTL_OPMODE_SHA512;

   //Start SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

   //Digest the message
   for(n = length; n >= 128; n -= 128)
   {
      //Update hash value
      hashProcessData(data, 128);
      //Advance the data pointer
      data = (uint8_t *) data + 128;
   }

   //Copy the partial block, is any
   osMemset(buffer, 0, 128);
   osMemcpy(buffer, data, n);

   //Append the first byte of the padding string
   buffer[n] = 0x80;

   //Pad the message so that its length is congruent to 112 modulo 128
   if(n >= 112)
   {
      hashProcessData(buffer, 128);
      osMemset(buffer, 0, 128);
   }

   //Append the length of the original message
   STORE64BE(length * 8, buffer + 120);

   //Process the final block
   hashProcessData(buffer, 128);

   //Save the resulting hash value
   temp = CRPT->HMAC_DGST[0];
   __UNALIGNED_UINT32_WRITE(digest, temp);
   temp = CRPT->HMAC_DGST[1];
   __UNALIGNED_UINT32_WRITE(digest + 4, temp);
   temp = CRPT->HMAC_DGST[2];
   __UNALIGNED_UINT32_WRITE(digest + 8, temp);
   temp = CRPT->HMAC_DGST[3];
   __UNALIGNED_UINT32_WRITE(digest + 12, temp);
   temp = CRPT->HMAC_DGST[4];
   __UNALIGNED_UINT32_WRITE(digest + 16, temp);
   temp = CRPT->HMAC_DGST[5];
   __UNALIGNED_UINT32_WRITE(digest + 20, temp);
   temp = CRPT->HMAC_DGST[6];
   __UNALIGNED_UINT32_WRITE(digest + 24, temp);
   temp = CRPT->HMAC_DGST[7];
   __UNALIGNED_UINT32_WRITE(digest + 28, temp);
   temp = CRPT->HMAC_DGST[8];
   __UNALIGNED_UINT32_WRITE(digest + 32, temp);
   temp = CRPT->HMAC_DGST[9];
   __UNALIGNED_UINT32_WRITE(digest + 36, temp);
   temp = CRPT->HMAC_DGST[10];
   __UNALIGNED_UINT32_WRITE(digest + 40, temp);
   temp = CRPT->HMAC_DGST[11];
   __UNALIGNED_UINT32_WRITE(digest + 44, temp);
   temp = CRPT->HMAC_DGST[12];
   __UNALIGNED_UINT32_WRITE(digest + 48, temp);
   temp = CRPT->HMAC_DGST[13];
   __UNALIGNED_UINT32_WRITE(digest + 52, temp);
   temp = CRPT->HMAC_DGST[14];
   __UNALIGNED_UINT32_WRITE(digest + 56, temp);
   temp = CRPT->HMAC_DGST[15];
   __UNALIGNED_UINT32_WRITE(digest + 60, temp);

   //Stop SHA engine
   CRPT->HMAC_CTL |= CRPT_HMAC_CTL_STOP_Msk;

   //Release exclusive access to the CRYPTO module
   osReleaseMutex(&m480CryptoMutex);

   //Sucessful processing
   return NO_ERROR;
}

#endif
#endif
