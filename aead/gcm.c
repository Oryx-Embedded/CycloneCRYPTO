/**
 * @file gcm.c
 * @brief Galois/Counter Mode (GCM)
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
 * The Galois/Counter Mode (GCM) is an authenticated encryption algorithm
 * designed to provide both data authenticity (integrity) and confidentiality.
 * Refer to SP 800-38D for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "aead/gcm.h"
#include "debug.h"

//Check crypto library configuration
#if (GCM_SUPPORT == ENABLED)

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
 * @brief Initialize GCM context
 * @param[in] context Pointer to the GCM context
 * @param[in] cipherAlgo Cipher algorithm
 * @param[in] cipherContext Pointer to the cipher algorithm context
 * @return Error code
 **/

error_t gcmInit(GcmContext *context, const CipherAlgo *cipherAlgo, void *cipherContext)
{
   uint_t i;
   uint_t j;
   uint32_t c;
   uint32_t h[4];

   //GCM supports only symmetric block ciphers whose block size is 128 bits
   if(cipherAlgo->type != CIPHER_ALGO_TYPE_BLOCK || cipherAlgo->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //Save cipher algorithm context
   context->cipherAlgo = cipherAlgo;
   context->cipherContext = cipherContext;

   //Let H = 0
   h[0] = 0;
   h[1] = 0;
   h[2] = 0;
   h[3] = 0;

   //Generate the hash subkey H
   context->cipherAlgo->encryptBlock(context->cipherContext,
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

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Authenticated encryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmEncrypt(GcmContext *context, const uint8_t *iv, size_t ivLen, const uint8_t *a,
   size_t aLen, const uint8_t *p, uint8_t *c, size_t length, uint8_t *t, size_t tLen)
{
   size_t k;
   size_t n;
   uint8_t b[16];
   uint8_t j[16];
   uint8_t s[16];

   //Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
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
         gcmXorBlock(j, j, iv, k);
         gcmMul(context, j);

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
      gcmXorBlock(j, j, b, 16);
      gcmMul(context, j);
   }

   //Compute MSB(CIPH(J(0)))
   context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
   cryptoMemcpy(t, b, tLen);

   //Initialize GHASH calculation
   cryptoMemset(s, 0, 16);
   //Length of the AAD
   n = aLen;

   //Process AAD
   while(n > 0)
   {
      //Additional data are processed in a block-by-block fashion
      k = MIN(n, 16);

      //Apply GHASH function
      gcmXorBlock(s, s, a, k);
      gcmMul(context, s);

      //Next block
      a += k;
      n -= k;
   }

   //Length of the plaintext
   n = length;

   //Process plaintext
   while(n > 0)
   {
      //The encryption operates in a block-by-block fashion
      k = MIN(n, 16);

      //Increment counter
      gcmIncCounter(j);

      //Encrypt plaintext
      context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
      gcmXorBlock(c, p, b, k);

      //Apply GHASH function
      gcmXorBlock(s, s, c, k);
      gcmMul(context, s);

      //Next block
      p += k;
      c += k;
      n -= k;
   }

   //Append the 64-bit representation of the length of the AAD and the ciphertext
   STORE64BE(aLen * 8, b);
   STORE64BE(length * 8, b + 8);

   //The GHASH function is applied to the result to produce a single output block S
   gcmXorBlock(s, s, b, 16);
   gcmMul(context, s);

   //Let T = MSB(GCTR(J(0), S)
   gcmXorBlock(t, t, s, tLen);

   //Successful encryption
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using GCM
 * @param[in] context Pointer to the GCM context
 * @param[in] iv Initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t Authentication tag
 * @param[in] tLen Length of the authentication tag
 * @return Error code
 **/

error_t gcmDecrypt(GcmContext *context, const uint8_t *iv, size_t ivLen, const uint8_t *a,
   size_t aLen, const uint8_t *c, uint8_t *p, size_t length, const uint8_t *t, size_t tLen)
{
   size_t k;
   size_t n;
   uint8_t b[16];
   uint8_t j[16];
   uint8_t r[16];
   uint8_t s[16];

   ///Make sure the GCM context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The length of the IV shall meet SP 800-38D requirements
   if(ivLen < 1)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the authentication tag
   if(tLen < 4 || tLen > 16)
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
         gcmXorBlock(j, j, iv, k);
         gcmMul(context, j);

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
      gcmXorBlock(j, j, b, 16);
      gcmMul(context, j);
   }

   //Compute MSB(CIPH(J(0)))
   context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
   cryptoMemcpy(r, b, tLen);

   //Initialize GHASH calculation
   cryptoMemset(s, 0, 16);
   //Length of the AAD
   n = aLen;

   //Process AAD
   while(n > 0)
   {
      //Additional data are processed in a block-by-block fashion
      k = MIN(n, 16);

      //Apply GHASH function
      gcmXorBlock(s, s, a, k);
      gcmMul(context, s);

      //Next block
      a += k;
      n -= k;
   }

   //Length of the ciphertext
   n = length;

   //Process ciphertext
   while(n > 0)
   {
      //The decryption operates in a block-by-block fashion
      k = MIN(n, 16);

      //Apply GHASH function
      gcmXorBlock(s, s, c, k);
      gcmMul(context, s);

      //Increment counter
      gcmIncCounter(j);

      //Decrypt ciphertext
      context->cipherAlgo->encryptBlock(context->cipherContext, j, b);
      gcmXorBlock(p, c, b, k);

      //Next block
      c += k;
      p += k;
      n -= k;
   }

   //Append the 64-bit representation of the length of the AAD and the ciphertext
   STORE64BE(aLen * 8, b);
   STORE64BE(length * 8, b + 8);

   //The GHASH function is applied to the result to produce a single output block S
   gcmXorBlock(s, s, b, 16);
   gcmMul(context, s);

   //Let R = MSB(GCTR(J(0), S))
   gcmXorBlock(r, r, s, tLen);

   //The calculated tag is bitwise compared to the received tag. The
   //message is authenticated if and only if the tags match
   if(cryptoMemcmp(r, t, tLen))
      return ERROR_FAILURE;

   //Successful decryption
   return NO_ERROR;
}


/**
 * @brief Multiplication operation in GF(2^128)
 * @param[in] context Pointer to the GCM context
 * @param[in, out] x 16-byte block to be multiplied by H
 **/

void gcmMul(GcmContext *context, uint8_t *x)
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

void gcmXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
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

void gcmIncCounter(uint8_t *x)
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
