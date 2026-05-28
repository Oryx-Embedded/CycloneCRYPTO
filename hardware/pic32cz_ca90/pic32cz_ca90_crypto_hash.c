/**
 * @file pic32cz_ca90_crypto_hash.c
 * @brief PIC32CZ CA90 hash hardware accelerator
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "pic32c.h"
#include "hsm_hash.h"
#include "core/crypto.h"
#include "hardware/pic32cz_ca90/pic32cz_ca90_crypto.h"
#include "hardware/pic32cz_ca90/pic32cz_ca90_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (PIC32CZ_CA90_CRYPTO_HASH_SUPPORT == ENABLED)

//Padding string
static const uint8_t padding[128] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/**
 * @brief Update hash value
 * @param[in] type Hash algorithm
 * @param[in] data Pointer to the input buffer
 * @param[in] length Length of the input buffer
 * @param[in,out] h Intermediate hash value
 * @return Error code
 **/

error_t hashProcessData(hsm_Hash_Types_E type, const uint8_t *data,
   size_t length, uint32_t *h)
{
   hsm_Cmd_Status_E status;

   //Acquire exclusive access to the HSM
   osAcquireMutex(&pic32czca90CryptoMutex);

   //Digest the message
   status = HSM_Hash_UpdateCmd((uint8_t *) h, (uint8_t *) data, length, type);

   //Release exclusive access to the HSM
   osReleaseMutex(&pic32czca90CryptoMutex);

   //Return status code
   return (status == HSM_CMD_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
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
   hsm_Cmd_Status_E status;

   //Acquire exclusive access to the HSM
   osAcquireMutex(&pic32czca90CryptoMutex);

   //Digest the message
   status = HSM_Hash_DigestDirect(HSM_CMD_HASH_SHA1, (uint8_t *) data,
      length, digest);

   //Release exclusive access to the HSM
   osReleaseMutex(&pic32czca90CryptoMutex);

   //Return status code
   return (status == HSM_CMD_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-1 message digest context
 * @param[in] context Pointer to the SHA-1 context to initialize
 **/

void sha1Init(Sha1Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0x67452301);
   context->h[1] = BETOH32(0xEFCDAB89);
   context->h[2] = BETOH32(0x98BADCFE);
   context->h[3] = BETOH32(0x10325476);
   context->h[4] = BETOH32(0xC3D2E1F0);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-1 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-1 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(HSM_CMD_HASH_SHA1, data, n, context->h);

         //Update the SHA-1 context
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-1 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(HSM_CMD_HASH_SHA1, context->buffer,
               context->size, context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-1 message digest
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest
 **/

void sha1Final(Sha1Context *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(context->size < 56)
   {
      paddingSize = 56 - context->size;
   }
   else
   {
      paddingSize = 64 + 56 - context->size;
   }

   //Append padding
   sha1Update(context, padding, paddingSize);

   //Append the length of the original message
   for(i = 0; i < 8; i++)
   {
      context->buffer[63 - i] = totalSize & 0xFF;
      totalSize >>= 8;
   }

   //Calculate the message digest
   hashProcessData(HSM_CMD_HASH_SHA1, context->buffer, 64,
      context->h);

   //Copy the resulting digest
   for(i = 0; i < (SHA1_DIGEST_SIZE / 4); i++)
   {
      STORE32LE(context->h[i], digest + i * 4);
   }
}


/**
 * @brief Finish the SHA-1 message digest (no padding added)
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest
 **/

void sha1FinalRaw(Sha1Context *context, uint8_t *digest)
{
   uint_t i;

   //Copy the resulting digest
   for(i = 0; i < (SHA1_DIGEST_SIZE / 4); i++)
   {
      STORE32LE(context->h[i], digest + i * 4);
   }
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
   hsm_Cmd_Status_E status;

   //Acquire exclusive access to the HSM
   osAcquireMutex(&pic32czca90CryptoMutex);

   //Digest the message
   status = HSM_Hash_DigestDirect(HSM_CMD_HASH_SHA224, (uint8_t *) data,
      length, digest);

   //Release exclusive access to the HSM
   osReleaseMutex(&pic32czca90CryptoMutex);

   //Return status code
   return (status == HSM_CMD_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-224 message digest context
 * @param[in] context Pointer to the SHA-224 context to initialize
 **/

void sha224Init(Sha224Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0xC1059ED8);
   context->h[1] = BETOH32(0x367CD507);
   context->h[2] = BETOH32(0x3070DD17);
   context->h[3] = BETOH32(0xF70E5939);
   context->h[4] = BETOH32(0xFFC00B31);
   context->h[5] = BETOH32(0x68581511);
   context->h[6] = BETOH32(0x64F98FA7);
   context->h[7] = BETOH32(0xBEFA4FA4);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
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
   hsm_Cmd_Status_E status;

   //Acquire exclusive access to the HSM
   osAcquireMutex(&pic32czca90CryptoMutex);

   //Digest the message
   status = HSM_Hash_DigestDirect(HSM_CMD_HASH_SHA256, (uint8_t *) data,
      length, digest);

   //Release exclusive access to the HSM
   osReleaseMutex(&pic32czca90CryptoMutex);

   //Return status code
   return (status == HSM_CMD_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

void sha256Init(Sha256Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH32(0x6A09E667);
   context->h[1] = BETOH32(0xBB67AE85);
   context->h[2] = BETOH32(0x3C6EF372);
   context->h[3] = BETOH32(0xA54FF53A);
   context->h[4] = BETOH32(0x510E527F);
   context->h[5] = BETOH32(0x9B05688C);
   context->h[6] = BETOH32(0x1F83D9AB);
   context->h[7] = BETOH32(0x5BE0CD19);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 64)
      {
         //The length must be a multiple of 64 bytes
         n = length - (length % 64);

         //Update hash value
         hashProcessData(HSM_CMD_HASH_SHA256, data, n, context->h);

         //Update the SHA-256 context
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 64 bytes
         n = MIN(length, 64 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-256 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 64)
         {
            //Update hash value
            hashProcessData(HSM_CMD_HASH_SHA256, context->buffer,
               context->size, context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest
 **/

void sha256Final(Sha256Context *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(context->size < 56)
   {
      paddingSize = 56 - context->size;
   }
   else
   {
      paddingSize = 64 + 56 - context->size;
   }

   //Append padding
   sha256Update(context, padding, paddingSize);

   //Append the length of the original message
   for(i = 0; i < 8; i++)
   {
      context->buffer[63 - i] = totalSize & 0xFF;
      totalSize >>= 8;
   }

   //Calculate the message digest
   hashProcessData(HSM_CMD_HASH_SHA256, context->buffer, 64,
      context->h);

   //Copy the resulting digest
   for(i = 0; i < (SHA256_DIGEST_SIZE / 4); i++)
   {
      STORE32LE(context->h[i], digest + i * 4);
   }
}


/**
 * @brief Finish the SHA-256 message digest (no padding added)
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest
 **/

void sha256FinalRaw(Sha256Context *context, uint8_t *digest)
{
   uint_t i;

   //Copy the resulting digest
   for(i = 0; i < (SHA256_DIGEST_SIZE / 4); i++)
   {
      STORE32LE(context->h[i], digest + i * 4);
   }
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
   hsm_Cmd_Status_E status;

   //Acquire exclusive access to the HSM
   osAcquireMutex(&pic32czca90CryptoMutex);

   //Digest the message
   status = HSM_Hash_DigestDirect(HSM_CMD_HASH_SHA384, (uint8_t *) data,
      length, digest);

   //Release exclusive access to the HSM
   osReleaseMutex(&pic32czca90CryptoMutex);

   //Return status code
   return (status == HSM_CMD_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-384 message digest context
 * @param[in] context Pointer to the SHA-384 context to initialize
 **/

void sha384Init(Sha384Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0xCBBB9D5DC1059ED8);
   context->h[1] = BETOH64(0x629A292A367CD507);
   context->h[2] = BETOH64(0x9159015A3070DD17);
   context->h[3] = BETOH64(0x152FECD8F70E5939);
   context->h[4] = BETOH64(0x67332667FFC00B31);
   context->h[5] = BETOH64(0x8EB44A8768581511);
   context->h[6] = BETOH64(0xDB0C2E0D64F98FA7);
   context->h[7] = BETOH64(0x47B5481DBEFA4FA4);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Finish the SHA-384 message digest (no padding added)
 * @param[in] context Pointer to the SHA-384 context
 * @param[out] digest Calculated digest
 **/

void sha384FinalRaw(Sha384Context *context, uint8_t *digest)
{
   uint_t i;

   //Copy the resulting digest
   for(i = 0; i < (SHA384_DIGEST_SIZE / 8); i++)
   {
      STORE64LE(context->h[i], digest + i * 8);
   }
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
   hsm_Cmd_Status_E status;

   //Acquire exclusive access to the HSM
   osAcquireMutex(&pic32czca90CryptoMutex);

   //Digest the message
   status = HSM_Hash_DigestDirect(HSM_CMD_HASH_SHA512, (uint8_t *) data,
      length, digest);

   //Release exclusive access to the HSM
   osReleaseMutex(&pic32czca90CryptoMutex);

   //Return status code
   return (status == HSM_CMD_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-512 message digest context
 * @param[in] context Pointer to the SHA-512 context to initialize
 **/

void sha512Init(Sha512Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x6A09E667F3BCC908);
   context->h[1] = BETOH64(0xBB67AE8584CAA73B);
   context->h[2] = BETOH64(0x3C6EF372FE94F82B);
   context->h[3] = BETOH64(0xA54FF53A5F1D36F1);
   context->h[4] = BETOH64(0x510E527FADE682D1);
   context->h[5] = BETOH64(0x9B05688C2B3E6C1F);
   context->h[6] = BETOH64(0x1F83D9ABFB41BD6B);
   context->h[7] = BETOH64(0x5BE0CD19137E2179);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-512 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-512 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha512Update(Sha512Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //Check whether some data is pending in the buffer
      if(context->size == 0 && length >= 128)
      {
         //The length must be a multiple of 128 bytes
         n = length - (length % 128);

         //Update hash value
         hashProcessData(HSM_CMD_HASH_SHA512, data, n,
            (uint32_t *) context->h);

         //Update the SHA-512 context
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;
      }
      else
      {
         //The buffer can hold at most 128 bytes
         n = MIN(length, 128 - context->size);

         //Copy the data to the buffer
         osMemcpy(context->buffer + context->size, data, n);

         //Update the SHA-512 context
         context->size += n;
         context->totalSize += n;
         //Advance the data pointer
         data = (uint8_t *) data + n;
         //Remaining bytes to process
         length -= n;

         //Check whether the buffer is full
         if(context->size == 128)
         {
            //Update hash value
            hashProcessData(HSM_CMD_HASH_SHA512, context->buffer,
               context->size, (uint32_t *) context->h);

            //Empty the buffer
            context->size = 0;
         }
      }
   }
}


/**
 * @brief Finish the SHA-512 message digest
 * @param[in] context Pointer to the SHA-512 context
 * @param[out] digest Calculated digest
 **/

void sha512Final(Sha512Context *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 112 modulo 128
   if(context->size < 112)
   {
      paddingSize = 112 - context->size;
   }
   else
   {
      paddingSize = 128 + 112 - context->size;
   }

   //Append padding
   sha512Update(context, padding, paddingSize);

   //Append the length of the original message
   for(i = 0; i < 16; i++)
   {
      context->buffer[127 - i] = totalSize & 0xFF;
      totalSize >>= 8;
   }

   //Calculate the message digest
   hashProcessData(HSM_CMD_HASH_SHA512, context->buffer, 128,
      (uint32_t *) context->h);

   //Copy the resulting digest
   for(i = 0; i < (SHA512_DIGEST_SIZE / 8); i++)
   {
      STORE64LE(context->h[i], digest + i * 8);
   }
}

#endif
#if (SHA512_224_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512/224 message digest context
 * @param[in] context Pointer to the SHA-512/224 context to initialize
 **/

void sha512_224Init(Sha512_224Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x8C3D37C819544DA2);
   context->h[1] = BETOH64(0x73E1996689DCD4D6);
   context->h[2] = BETOH64(0x1DFAB7AE32FF9C82);
   context->h[3] = BETOH64(0x679DD514582F9FCF);
   context->h[4] = BETOH64(0x0F6D2B697BD44DA8);
   context->h[5] = BETOH64(0x77E36F7304C48942);
   context->h[6] = BETOH64(0x3F9D85A86A1D36C8);
   context->h[7] = BETOH64(0x1112E6AD91D692A1);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

#endif
#if (SHA512_256_SUPPORT == ENABLED)

/**
 * @brief Initialize SHA-512/256 message digest context
 * @param[in] context Pointer to the SHA-512/256 context to initialize
 **/

void sha512_256Init(Sha512_256Context *context)
{
   //Set initial hash value
   context->h[0] = BETOH64(0x22312194FC2BF72C);
   context->h[1] = BETOH64(0x9F555FA3C84C64C2);
   context->h[2] = BETOH64(0x2393B86B6F53B151);
   context->h[3] = BETOH64(0x963877195940EABD);
   context->h[4] = BETOH64(0x96283EE2A88EFFE3);
   context->h[5] = BETOH64(0xBE5E1E2553863992);
   context->h[6] = BETOH64(0x2B0199FC2C85B8AA);
   context->h[7] = BETOH64(0x0EB72DDC81C52CA2);

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}

#endif
#endif
