/**
 * @file gmac.c
 * @brief GMAC (Galois Message Authentication Code)
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
 * GMAC is a message authentication code (MAC) based on GCM. Refer to
 * SP 800-38D for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "mac/gmac.h"

//Check crypto library configuration
#if (GMAC_SUPPORT == ENABLED)

//Reduction table
static const uint32_t r[16] =
{
   0x00000000,
   0x1C200000,
   0x38400000,
   0x24600000,
   0x70800000,
   0x6CA00000,
   0x48C00000,
   0x54E00000,
   0xE1000000,
   0xFD200000,
   0xD9400000,
   0xC5600000,
   0x91800000,
   0x8DA00000,
   0xA9C00000,
   0xB5E00000
};


/**
 * @brief Compute GMAC using the specified cipher algorithm
 * @param[in] cipher Cipher algorithm used to compute GMAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] data Pointer to the input message
 * @param[in] dataLen Length of the input data
 * @param[out] mac Calculated MAC value
 * @param[in] macLen Expected length of the MAC
 * @return Error code
 **/

error_t gmacCompute(const CipherAlgo *cipher, const void *key, size_t keyLen,
   const uint8_t *iv, size_t ivLen, const void *data, size_t dataLen,
   uint8_t *mac, size_t macLen)
{
   error_t error;
   GmacContext *context;

   //Allocate a memory buffer to hold the GMAC context
   context = cryptoAllocMem(sizeof(GmacContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the GMAC context
      error = gmacInit(context, cipher, key, keyLen);

      //Check status code
      if(!error)
      {
         //Reset GMAC context
         error = gmacReset(context, iv, ivLen);
      }

      //Check status code
      if(!error)
      {
         //Digest the message
         gmacUpdate(context, data, dataLen);
         //Finalize the GMAC computation
         error = gmacFinal(context, mac, macLen);
      }

      //Free previously allocated memory
      cryptoFreeMem(context);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Initialize GMAC calculation
 * @param[in] context Pointer to the GMAC context to initialize
 * @param[in] cipher Cipher algorithm used to compute GMAC
 * @param[in] key Pointer to the secret key
 * @param[in] keyLen Length of the secret key
 * @return Error code
 **/

error_t gmacInit(GmacContext *context, const CipherAlgo *cipher,
   const void *key, size_t keyLen)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint32_t c;
   uint32_t h[4];

   //GMAC supports only symmetric block ciphers whose block size is 128 bits
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK || cipher->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //Cipher algorithm used to compute GMAC
   context->cipher = cipher;

   //Initialize cipher context
   error = cipher->init(context->cipherContext, key, keyLen);
   //Any error to report?
   if(error)
      return error;

   //Let H = 0
   h[0] = 0;
   h[1] = 0;
   h[2] = 0;
   h[3] = 0;

   //Generate the hash subkey H
   context->cipher->encryptBlock(context->cipherContext,
      (uint8_t *) h, (uint8_t *) h);

   //Pre-compute M(0) = H * 0
   j = reverseInt4(0);
   context->m[j][0] = 0;
   context->m[j][1] = 0;
   context->m[j][2] = 0;
   context->m[j][3] = 0;

   //Pre-compute M(1) = H * 1
   j = reverseInt4(1);
   context->m[j][0] = betoh32(h[3]);
   context->m[j][1] = betoh32(h[2]);
   context->m[j][2] = betoh32(h[1]);
   context->m[j][3] = betoh32(h[0]);

   //Pre-compute all 4-bit multiples of H
   for(i = 2; i < 16; i++)
   {
      //Odd value?
      if(i & 1)
      {
         //Compute M(i) = M(i - 1) + H
         j = reverseInt4(i - 1);
         h[0] = context->m[j][0];
         h[1] = context->m[j][1];
         h[2] = context->m[j][2];
         h[3] = context->m[j][3];

         //An addition in GF(2^128) is identical to a bitwise
         //exclusive-OR operation
         j = reverseInt4(1);
         h[0] ^= context->m[j][0];
         h[1] ^= context->m[j][1];
         h[2] ^= context->m[j][2];
         h[3] ^= context->m[j][3];
      }
      //Even value?
      else
      {
         //Compute M(i) = M(i / 2) * x
         j = reverseInt4(i / 2);
         h[0] = context->m[j][0];
         h[1] = context->m[j][1];
         h[2] = context->m[j][2];
         h[3] = context->m[j][3];

         //The multiplication of a polynomial by x in GF(2^128) corresponds
         //to a shift of indices
         c = h[0] & 0x01;
         h[0] = (h[0] >> 1) | (h[1] << 31);
         h[1] = (h[1] >> 1) | (h[2] << 31);
         h[2] = (h[2] >> 1) | (h[3] << 31);
         h[3] >>= 1;

         //If the highest term of the result is equal to one, then perform
         //reduction
         h[3] ^= r[reverseInt4(1)] & ~(c - 1);
      }

      //Save M(i)
      j = reverseInt4(i);
      context->m[j][0] = h[0];
      context->m[j][1] = h[1];
      context->m[j][2] = h[2];
      context->m[j][3] = h[3];
   }

   //Clear input buffer
   cryptoMemset(context->buffer, 0, context->cipher->blockSize);
   //Number of bytes in the buffer
   context->bufferLength = 0;
   //Total number of bytes
   context->totalLength = 0;

   //Initialize MAC value
   cryptoMemset(context->mac, 0, context->cipher->blockSize);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Reset GMAC context
 * @param[in] context Pointer to the GMAC context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @return Error code
 **/

error_t gmacReset(GmacContext *context, const uint8_t *iv, size_t ivLen)
{
   size_t k;
   size_t n;
   uint8_t b[16];
   uint8_t j[16];

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_PARAMETER;

   //Check whether the length of the IV is 96 bits
   if(ivLen == 12)
   {
      //When the length of the IV is 96 bits, the padding string is
      //appended to the IV to form the pre-counter block
      cryptoMemcpy(j, iv, 12);
      STORE32BE(1, j + 12);
   }
   else
   {
      //Initialize GHASH calculation
      cryptoMemset(j, 0, 16);

      //Length of the IV
      n = ivLen;

      //Process the initialization vector
      while(n > 0)
      {
         //The IV processed in a block-by-block fashion
         k = MIN(n, 16);

         //Apply GHASH function
         gmacXorBlock(j, j, iv, k);
         gmacMul(context, j);

         //Next block
         iv += k;
         n -= k;
      }

      //The string is appended with 64 additional 0 bits, followed by the
      //64-bit representation of the length of the IV
      cryptoMemset(b, 0, 8);
      STORE64BE(ivLen * 8, b + 8);

      //The GHASH function is applied to the resulting string to form the
      //pre-counter block
      gmacXorBlock(j, j, b, 16);
      gmacMul(context, j);
   }

   //Compute MSB(CIPH(J(0)))
   context->cipher->encryptBlock(context->cipherContext, j, b);
   cryptoMemcpy(context->mac, b, 16);

   //Initialize GHASH calculation
   cryptoMemset(context->s, 0, 16);

   //Clear input buffer
   cryptoMemset(context->buffer, 0, context->cipher->blockSize);
   //Number of bytes in the buffer
   context->bufferLength = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Update the GMAC context with a portion of the message being hashed
 * @param[in] context Pointer to the GMAC context
 * @param[in] data Pointer to the input data
 * @param[in] dataLen Length of the buffer
 **/

void gmacUpdate(GmacContext *context, const void *data, size_t dataLen)
{
   size_t n;

   //Process the incoming data
   while(dataLen > 0)
   {
      //The message is partitioned into complete blocks
      n = MIN(dataLen, 16 - context->bufferLength);

      //Copy the data to the buffer
      cryptoMemcpy(context->buffer + context->bufferLength, data, n);
      //Update the length of the buffer
      context->bufferLength += n;
      //Update the total number of bytes
      context->totalLength += n;

      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      dataLen -= n;

      //Process message block by block
      if(context->bufferLength == 16)
      {
         //Apply GHASH function
         gmacXorBlock(context->s, context->s, context->buffer, 16);
         gmacMul(context, context->s);

         //Empty the buffer
         context->bufferLength = 0;
      }
   }
}


/**
 * @brief Finish the GMAC calculation
 * @param[in] context Pointer to the GMAC context
 * @param[out] mac Calculated MAC value
 * @param[in] macLen Expected length of the MAC
 **/

error_t gmacFinal(GmacContext *context, uint8_t *mac, size_t macLen)
{
   //Check the length of the MAC
   if(macLen < 4 || macLen > 16)
      return ERROR_INVALID_PARAMETER;

   //Process the last block of the message
   if(context->bufferLength > 0)
   {
      //Apply GHASH function
      gmacXorBlock(context->s, context->s, context->buffer, context->bufferLength);
      gmacMul(context, context->s);
   }

   //Append the 64-bit representation of the length of the message followed
   //by 64 additional 0 bits
   STORE64BE(context->totalLength * 8, context->buffer);
   cryptoMemset(context->buffer + 8, 0, 8);

   //The GHASH function is applied to the result to produce a single output block S
   gmacXorBlock(context->s, context->s, context->buffer, 16);
   gmacMul(context, context->s);

   //Let T = GCTR(J(0), S)
   gmacXorBlock(context->mac, context->mac, context->s, 16);

   //Copy the resulting MAC value
   if(mac != NULL)
   {
      //Output MSB(T)
      cryptoMemcpy(mac, context->mac, macLen);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Multiplication operation in GF(2^128)
 * @param[in] context Pointer to the GMAC context
 * @param[in, out] x 16-byte block to be multiplied by H
 **/

void gmacMul(GmacContext *context, uint8_t *x)
{
   int_t i;
   uint8_t b;
   uint8_t c;
   uint32_t z[4];

   //Let Z = 0
   z[0] = 0;
   z[1] = 0;
   z[2] = 0;
   z[3] = 0;

   //Fast table-driven implementation
   for(i = 15; i >= 0; i--)
   {
      //Get the lower nibble
      b = x[i] & 0x0F;

      //Multiply 4 bits at a time
      c = z[0] & 0x0F;
      z[0] = (z[0] >> 4) | (z[1] << 28);
      z[1] = (z[1] >> 4) | (z[2] << 28);
      z[2] = (z[2] >> 4) | (z[3] << 28);
      z[3] >>= 4;

      z[0] ^= context->m[b][0];
      z[1] ^= context->m[b][1];
      z[2] ^= context->m[b][2];
      z[3] ^= context->m[b][3];

      //Perform reduction
      z[3] ^= r[c];

      //Get the upper nibble
      b = (x[i] >> 4) & 0x0F;

      //Multiply 4 bits at a time
      c = z[0] & 0x0F;
      z[0] = (z[0] >> 4) | (z[1] << 28);
      z[1] = (z[1] >> 4) | (z[2] << 28);
      z[2] = (z[2] >> 4) | (z[3] << 28);
      z[3] >>= 4;

      z[0] ^= context->m[b][0];
      z[1] ^= context->m[b][1];
      z[2] ^= context->m[b][2];
      z[3] ^= context->m[b][3];

      //Perform reduction
      z[3] ^= r[c];
   }

   //Save the result
   STORE32BE(z[3], x);
   STORE32BE(z[2], x + 4);
   STORE32BE(z[1], x + 8);
   STORE32BE(z[0], x + 12);
}


/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First block
 * @param[in] b Second block
 * @param[in] n Size of the block
 **/

void gmacXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
{
   size_t i;

   //Perform XOR operation
   for(i = 0; i < n; i++)
   {
      x[i] = a[i] ^ b[i];
   }
}


/**
 * @brief Increment counter block
 * @param[in,out] x Pointer to the counter block
 **/

void gmacIncCounter(uint8_t *x)
{
   size_t i;

   //The function increments the right-most 32 bits of the block. The remaining
   //left-most 96 bits remain unchanged
   for(i = 0; i < 4; i++)
   {
      //Increment the current byte and propagate the carry if necessary
      if(++(x[15 - i]) != 0)
      {
         break;
      }
   }
}

#endif
