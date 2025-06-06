/**
 * @file sm3.c
 * @brief SM3 hash function
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
#include "core/crypto.h"
#include "hash/sm3.h"

//Check crypto library configuration
#if (SM3_SUPPORT == ENABLED)

//Macro to access the workspace as a circular buffer
#define W(n) w[(n) & 0x0F]

//SM3 auxiliary functions
#define FF1(x, y, z) ((x) ^ (y) ^ (z))
#define FF2(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG1(x, y, z) ((x) ^ (y) ^ (z))
#define GG2(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define P0(x) ((x) ^ ROL32(x, 9) ^ ROL32(x, 17))
#define P1(x) ((x) ^ ROL32(x, 15) ^ ROL32(x, 23))

//Constants T_j
#define TJ1 0x79CC4519
#define TJ2 0x7A879D8A

//SM3 padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//SM3 object identifier (1.0.10118.3.0.65)
const uint8_t SM3_OID[6] = {0x28, 0xCF, 0x06, 0x03, 0x00, 0x41};

//Common interface for hash algorithms
const HashAlgo sm3HashAlgo =
{
   "SM3",
   SM3_OID,
   sizeof(SM3_OID),
   sizeof(Sm3Context),
   SM3_BLOCK_SIZE,
   SM3_DIGEST_SIZE,
   SM3_MIN_PAD_SIZE,
   TRUE,
   (HashAlgoCompute) sm3Compute,
   (HashAlgoInit) sm3Init,
   (HashAlgoUpdate) sm3Update,
   (HashAlgoFinal) sm3Final,
   NULL
};


/**
 * @brief Digest a message using SM3
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sm3Compute(const void *data, size_t length, uint8_t *digest)
{
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Sm3Context *context;
#else
   Sm3Context context[1];
#endif

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   if(digest == NULL)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the SM3 context
   context = cryptoAllocMem(sizeof(Sm3Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the SM3 context
   sm3Init(context);
   //Digest the message
   sm3Update(context, data, length);
   //Finalize the SM3 message digest
   sm3Final(context, digest);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SM3 message digest context
 * @param[in] context Pointer to the SM3 context to initialize
 **/

void sm3Init(Sm3Context *context)
{
   //Set initial hash value
   context->h[0] = 0x7380166F;
   context->h[1] = 0x4914B2B9;
   context->h[2] = 0x172442D7;
   context->h[3] = 0xDA8A0600;
   context->h[4] = 0xA96F30BC;
   context->h[5] = 0x163138AA;
   context->h[6] = 0xE38DEE4D;
   context->h[7] = 0xB0FB0E4E;

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SM3 context with a portion of the message being hashed
 * @param[in] context Pointer to the SM3 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

__weak_func void sm3Update(Sm3Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 64 bytes
      n = MIN(length, 64 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the SM3 context
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
         sm3ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the SM3 message digest
 * @param[in] context Pointer to the SM3 context
 * @param[out] digest Calculated digest
 **/

void sm3Final(Sm3Context *context, uint8_t *digest)
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
   sm3Update(context, padding, paddingSize);

   //Append the length of the original message
   for(i = 0; i < 8; i++)
   {
      context->buffer[63 - i] = totalSize & 0xFF;
      totalSize >>= 8;
   }

   //Calculate the message digest
   sm3ProcessBlock(context);

   //Copy the resulting digest
   for(i = 0; i < (SM3_DIGEST_SIZE / 4); i++)
   {
      STORE32BE(context->h[i], digest + i * 4);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SM3 context
 **/

__weak_func void sm3ProcessBlock(Sm3Context *context)
{
   uint_t i;
   uint32_t ss1;
   uint32_t ss2;
   uint32_t tt1;
   uint32_t tt2;
   uint32_t temp;

   //Initialize the 8 working registers
   uint32_t a = context->h[0];
   uint32_t b = context->h[1];
   uint32_t c = context->h[2];
   uint32_t d = context->h[3];
   uint32_t e = context->h[4];
   uint32_t f = context->h[5];
   uint32_t g = context->h[6];
   uint32_t h = context->h[7];

   //Process message in 16-word blocks
   uint32_t *w = context->w;

   //Convert from big-endian byte order to host byte order
   for(i = 0; i < 16; i++)
   {
      w[i] = LOAD32BE(context->buffer + i * 4);
   }

   //SM3 compression function
   for(i = 0; i < 64; i++)
   {
      //Message expansion
      if(i >= 12)
      {
         temp = W(i + 4) ^ W(i + 11) ^ ROL32(W(i + 1), 15);
         W(i + 4) = P1(temp) ^ ROL32(W(i + 7), 7) ^ W(i + 14);
      }

      //Calculate TT1 and TT2
      if(i < 16)
      {
         temp = ROL32(a, 12) + e + ROL32(TJ1, i);
         ss1 = ROL32(temp, 7);
         ss2 = ss1 ^ ROL32(a, 12);
         tt1 = FF1(a, b, c) + d + ss2 + (W(i) ^ W(i + 4));
         tt2 = GG1(e, f, g) + h + ss1 + W(i);
      }
      else
      {
         temp = ROL32(a, 12) + e + ROL32(TJ2, i % 32);
         ss1 = ROL32(temp, 7);
         ss2 = ss1 ^ ROL32(a, 12);
         tt1 = FF2(a, b, c) + d + ss2 + (W(i) ^ W(i + 4));
         tt2 = GG2(e, f, g) + h + ss1 + W(i);
      }

      //Update working registers
      d = c;
      c = ROL32(b, 9);
      b = a;
      a = tt1;
      h = g;
      g = ROL32(f, 19);
      f = e;
      e = P0(tt2);
   }

   //Update the hash value
   context->h[0] ^= a;
   context->h[1] ^= b;
   context->h[2] ^= c;
   context->h[3] ^= d;
   context->h[4] ^= e;
   context->h[5] ^= f;
   context->h[6] ^= g;
   context->h[7] ^= h;
}

#endif
