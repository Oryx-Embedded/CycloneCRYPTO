/**
 * @file sha1.c
 * @brief SHA-1 (Secure Hash Algorithm 1)
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
 * @section Description
 *
 * SHA-1 is a secure hash algorithm for computing a condensed representation
 * of an electronic message. Refer to FIPS 180-4 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/sha1.h"

//Check crypto library configuration
#if (SHA1_SUPPORT == ENABLED)

//Macro to access the workspace as a circular buffer
#define W(n) w[(n) & 0x0F]

//SHA-1 auxiliary functions
#define CH(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))
#define MAJ(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

//SHA-1 padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//SHA-1 constants
static const uint32_t k[4] =
{
   0x5A827999,
   0x6ED9EBA1,
   0x8F1BBCDC,
   0xCA62C1D6
};

//SHA-1 object identifier (1.3.14.3.2.26)
const uint8_t SHA1_OID[5] = {0x2B, 0x0E, 0x03, 0x02, 0x1A};

//Common interface for hash algorithms
const HashAlgo sha1HashAlgo =
{
   "SHA-1",
   SHA1_OID,
   sizeof(SHA1_OID),
   sizeof(Sha1Context),
   SHA1_BLOCK_SIZE,
   SHA1_DIGEST_SIZE,
   SHA1_MIN_PAD_SIZE,
   TRUE,
   (HashAlgoCompute) sha1Compute,
   (HashAlgoInit) sha1Init,
   (HashAlgoUpdate) sha1Update,
   (HashAlgoFinal) sha1Final,
#if ((defined(MIMXRT1050_CRYPTO_HASH_SUPPORT) && MIMXRT1050_CRYPTO_HASH_SUPPORT == ENABLED) || \
   (defined(MIMXRT1060_CRYPTO_HASH_SUPPORT) && MIMXRT1060_CRYPTO_HASH_SUPPORT == ENABLED) || \
   (defined(MIMXRT1160_CRYPTO_HASH_SUPPORT) && MIMXRT1160_CRYPTO_HASH_SUPPORT == ENABLED) || \
   (defined(MIMXRT1170_CRYPTO_HASH_SUPPORT) && MIMXRT1170_CRYPTO_HASH_SUPPORT == ENABLED))
   NULL,
#else
   (HashAlgoFinalRaw) sha1FinalRaw
#endif
};


/**
 * @brief Digest a message using SHA-1
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

__weak_func error_t sha1Compute(const void *data, size_t length, uint8_t *digest)
{
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Sha1Context *context;
#else
   Sha1Context context[1];
#endif

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   if(digest == NULL)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the SHA-1 context
   context = cryptoAllocMem(sizeof(Sha1Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the SHA-1 context
   sha1Init(context);
   //Digest the message
   sha1Update(context, data, length);
   //Finalize the SHA-1 message digest
   sha1Final(context, digest);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SHA-1 message digest context
 * @param[in] context Pointer to the SHA-1 context to initialize
 **/

__weak_func void sha1Init(Sha1Context *context)
{
   //Set initial hash value
   context->h[0] = 0x67452301;
   context->h[1] = 0xEFCDAB89;
   context->h[2] = 0x98BADCFE;
   context->h[3] = 0x10325476;
   context->h[4] = 0xC3D2E1F0;

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

__weak_func void sha1Update(Sha1Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
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

      //Process message in 16-word blocks
      if(context->size == 64)
      {
         //Transform the 16-word block
         sha1ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the SHA-1 message digest
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest
 **/

__weak_func void sha1Final(Sha1Context *context, uint8_t *digest)
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
   sha1ProcessBlock(context);

   //Copy the resulting digest
   for(i = 0; i < (SHA1_DIGEST_SIZE / 4); i++)
   {
      STORE32BE(context->h[i], digest + i * 4);
   }
}


/**
 * @brief Finish the SHA-1 message digest (no padding added)
 * @param[in] context Pointer to the SHA-1 context
 * @param[out] digest Calculated digest
 **/

__weak_func void sha1FinalRaw(Sha1Context *context, uint8_t *digest)
{
   uint_t i;

   //Copy the resulting digest
   for(i = 0; i < (SHA1_DIGEST_SIZE / 4); i++)
   {
      STORE32BE(context->h[i], digest + i * 4);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-1 context
 **/

__weak_func void sha1ProcessBlock(Sha1Context *context)
{
   uint_t i;
   uint32_t temp;

   //Initialize the 5 working registers
   uint32_t a = context->h[0];
   uint32_t b = context->h[1];
   uint32_t c = context->h[2];
   uint32_t d = context->h[3];
   uint32_t e = context->h[4];

   //Process message in 16-word blocks
   uint32_t *w = context->w;

   //Convert from big-endian byte order to host byte order
   for(i = 0; i < 16; i++)
   {
      w[i] = LOAD32BE(context->buffer + i * 4);
   }

   //SHA-1 hash computation (alternate method)
   for(i = 0; i < 80; i++)
   {
      //Prepare the message schedule
      if(i >= 16)
      {
         W(i) = ROL32(W(i + 13) ^ W(i + 8) ^ W(i + 2) ^ W(i), 1);
      }

      //Calculate T
      if(i < 20)
      {
         temp = ROL32(a, 5) + CH(b, c, d) + e + W(i) + k[0];
      }
      else if(i < 40)
      {
         temp = ROL32(a, 5) + PARITY(b, c, d) + e + W(i) + k[1];
      }
      else if(i < 60)
      {
         temp = ROL32(a, 5) + MAJ(b, c, d) + e + W(i) + k[2];
      }
      else
      {
         temp = ROL32(a, 5) + PARITY(b, c, d) + e + W(i) + k[3];
      }

      //Update working registers
      e = d;
      d = c;
      c = ROL32(b, 30);
      b = a;
      a = temp;
   }

   //Update the hash value
   context->h[0] += a;
   context->h[1] += b;
   context->h[2] += c;
   context->h[3] += d;
   context->h[4] += e;
}

#endif
