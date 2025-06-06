/**
 * @file poly1305.c
 * @brief Poly1305 message-authentication code
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
#include "mac/poly1305.h"
#include "debug.h"

//Check crypto library configuration
#if (POLY1305_SUPPORT == ENABLED)


/**
 * @brief Initialize Poly1305 message-authentication code computation
 * @param[in] context Pointer to the Poly1305 context to initialize
 * @param[in] key Pointer to the 256-bit key
 **/

void poly1305Init(Poly1305Context *context, const uint8_t *key)
{
   //The 256-bit key is partitioned into two parts, called r and s
   context->r[0] = LOAD32LE(key);
   context->r[1] = LOAD32LE(key + 4);
   context->r[2] = LOAD32LE(key + 8);
   context->r[3] = LOAD32LE(key + 12);
   context->s[0] = LOAD32LE(key + 16);
   context->s[1] = LOAD32LE(key + 20);
   context->s[2] = LOAD32LE(key + 24);
   context->s[3] = LOAD32LE(key + 28);

   //Certain bits of r are required to be 0
   context->r[0] &= 0x0FFFFFFF;
   context->r[1] &= 0x0FFFFFFC;
   context->r[2] &= 0x0FFFFFFC;
   context->r[3] &= 0x0FFFFFFC;

   //The accumulator is set to zero
   context->a[0] = 0;
   context->a[1] = 0;
   context->a[2] = 0;
   context->a[3] = 0;
   context->a[4] = 0;

   //Number of bytes in the buffer
   context->size = 0;
}


/**
 * @brief Update Poly1305 message-authentication code computation
 * @param[in] context Pointer to the Poly1305 context
 * @param[in] data Pointer to the input message
 * @param[in] length Length of the input message
 **/

void poly1305Update(Poly1305Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 16 bytes
      n = MIN(length, 16 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the Poly1305 context
      context->size += n;
      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;

      //Process message in 16-byte blocks
      if(context->size == 16)
      {
         //Transform the 16-byte block
         poly1305ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finalize Poly1305 message-authentication code computation
 * @param[in] context Pointer to the Poly1305 context
 * @param[out] tag Calculated message-authentication code
 **/

void poly1305Final(Poly1305Context *context, uint8_t *tag)
{
   uint64_t temp;
   uint32_t mask;
   uint32_t b[5];

   //Process the last block
   if(context->size != 0)
   {
      poly1305ProcessBlock(context);
   }

   //Perform modular reduction (2^130 = 5)
   temp = context->a[4] & 0xFFFFFFFC;
   temp += context->a[4] >> 2;
   temp += context->a[0];
   context->a[0] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[1];
   context->a[1] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[2];
   context->a[2] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[3];
   context->a[3] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[4];
   context->a[4] = temp & 0x00000003;

   //Compute b = a + 5
   temp = 5;
   temp += context->a[0];
   b[0] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[1];
   b[1] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[2];
   b[2] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[3];
   b[3] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += context->a[4];
   b[4] = temp & 0xFFFFFFFF;

   //If (a + 5) >= 2^130, form a mask with the value 0x00000000. Else,
   //form a mask with the value 0xffffffff
   mask = ((b[4] & 0x04) >> 2) - 1;

   //Select between (a % 2^128) and (b % 2^128)
   context->a[0] = (context->a[0] & mask) | (b[0] & ~mask);
   context->a[1] = (context->a[1] & mask) | (b[1] & ~mask);
   context->a[2] = (context->a[2] & mask) | (b[2] & ~mask);
   context->a[3] = (context->a[3] & mask) | (b[3] & ~mask);

   //Finally, the value of the secret key s is added to the accumulator
   temp = (uint64_t) context->a[0] + context->s[0];
   b[0] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[1] + context->s[1];
   b[1] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[2] + context->s[2];
   b[2] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[3] + context->s[3];
   b[3] = temp & 0xFFFFFFFF;

   //The result is serialized as a little-endian number, producing
   //the 16 byte tag
   STORE32LE(b[0], tag);
   STORE32LE(b[1], tag + 4);
   STORE32LE(b[2], tag + 8);
   STORE32LE(b[3], tag + 12);

   //Clear the accumulator
   context->a[0] = 0;
   context->a[1] = 0;
   context->a[2] = 0;
   context->a[3] = 0;
   context->a[4] = 0;

   //Clear r and s
   context->r[0] = 0;
   context->r[1] = 0;
   context->r[2] = 0;
   context->r[3] = 0;
   context->s[0] = 0;
   context->s[1] = 0;
   context->s[2] = 0;
   context->s[3] = 0;
}


/**
 * @brief Process message in 16-byte blocks
 * @param[in] context Pointer to the Poly1305 context
 **/

void poly1305ProcessBlock(Poly1305Context *context)
{
   uint_t n;
   uint64_t temp;
   uint32_t u[8];

   //Retrieve the length of the last block
   n = context->size;

   //Add one bit beyond the number of octets. For a 16-byte block,
   //this is equivalent to adding 2^128 to the number. For the shorter
   //block, it can be 2^120, 2^112, or any power of two that is evenly
   //divisible by 8, all the way down to 2^8
   context->buffer[n++] = 0x01;

   //If the resulting block is not 17 bytes long (the last block),
   //pad it with zeros
   while(n < 17)
   {
      context->buffer[n++] = 0x00;
   }

   //Read the block as a little-endian number
   u[0] = LOAD32LE(context->buffer);
   u[1] = LOAD32LE(context->buffer + 4);
   u[2] = LOAD32LE(context->buffer + 8);
   u[3] = LOAD32LE(context->buffer + 12);
   u[4] = context->buffer[16];

   //Add this number to the accumulator
   temp = (uint64_t) context->a[0] + u[0];
   context->a[0] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[1] + u[1];
   context->a[1] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[2] + u[2];
   context->a[2] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[3] + u[3];
   context->a[3] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[4] + u[4];
   context->a[4] = temp & 0xFFFFFFFF;

   //Multiply the accumulator by r
   temp = (uint64_t) context->a[0] * context->r[0];
   u[0] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[0] * context->r[1];
   temp += (uint64_t) context->a[1] * context->r[0];
   u[1] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[0] * context->r[2];
   temp += (uint64_t) context->a[1] * context->r[1];
   temp += (uint64_t) context->a[2] * context->r[0];
   u[2] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[0] * context->r[3];
   temp += (uint64_t) context->a[1] * context->r[2];
   temp += (uint64_t) context->a[2] * context->r[1];
   temp += (uint64_t) context->a[3] * context->r[0];
   u[3] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[1] * context->r[3];
   temp += (uint64_t) context->a[2] * context->r[2];
   temp += (uint64_t) context->a[3] * context->r[1];
   temp += (uint64_t) context->a[4] * context->r[0];
   u[4] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[2] * context->r[3];
   temp += (uint64_t) context->a[3] * context->r[2];
   temp += (uint64_t) context->a[4] * context->r[1];
   u[5] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[3] * context->r[3];
   temp += (uint64_t) context->a[4] * context->r[2];
   u[6] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += (uint64_t) context->a[4] * context->r[3];
   u[7] = temp & 0xFFFFFFFF;

   //Perform modular reduction
   temp = u[0];
   temp += u[4] & 0xFFFFFFFC;
   temp += (u[4] >> 2) | (u[5] << 30);
   context->a[0] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += u[1];
   temp += u[5];
   temp += (u[5] >> 2) | (u[6] << 30);
   context->a[1] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += u[2];
   temp += u[6];
   temp += (u[6] >> 2) | (u[7] << 30);
   context->a[2] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += u[3];
   temp += u[7];
   temp += u[7] >> 2;
   context->a[3] = temp & 0xFFFFFFFF;
   temp >>= 32;
   temp += u[4] & 0x00000003;
   context->a[4] = temp & 0xFFFFFFFF;
}

#endif
