/**
 * @file zuc.c
 * @brief ZUC stream cipher (ZUC-128 and ZUC-256)
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
 * ZUC-128 is a word-oriented stream cipher. It takes a 128-bit initial key and
 * a 128-bit initialization vector (IV) as input, and outputs a key stream of
 * 32-bit words. This key stream can be used for encryption/decryption. ZUC-256
 * is the successor of ZUC-128. It works with a 256-bit key and a 128 or 184-bit
 * initialization vector (IV)
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "cipher/zuc.h"

//Check crypto library configuration
#if (ZUC_SUPPORT == ENABLED)

//Addition modulo (2^31 - 1)
#define ADD31(x, a, b) \
{ \
   x = (a) + (b); \
   x = (x) + ((x) >> 31); \
   x &= 0x7FFFFFFF; \
}

//Multiplication by 2^n over GF(2^31 - 1)
#define MUL31(x, a, n) \
{ \
   x = ((a) << (n)) | ((a) >> (31 - (n))); \
   x &= 0x7FFFFFFF; \
}

//Shift operation
#define SHIFT496(s, s16) \
{ \
   s[0] = s[1]; \
   s[1] = s[2]; \
   s[2] = s[3]; \
   s[3] = s[4]; \
   s[4] = s[5]; \
   s[5] = s[6]; \
   s[6] = s[7]; \
   s[7] = s[8]; \
   s[8] = s[9]; \
   s[9] = s[10]; \
   s[10] = s[11]; \
   s[11] = s[12]; \
   s[12] = s[13]; \
   s[13] = s[14]; \
   s[14] = s[15]; \
   s[15] = s16; \
}

//Linear feedback shift register (initialization mode)
#define LFSR_WITH_INIT_MODE(s, u) \
{ \
   uint32_t s16; \
   uint32_t temp; \
   s16 = s[0]; \
   MUL31(temp, s[0], 8); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[4], 20); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[10], 21); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[13], 17); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[15], 15); \
   ADD31(s16, s16, temp); \
   ADD31(s16, s16, u); \
   SHIFT496(s, s16); \
}

//Linear feedback shift register (working mode)
#define LFSR_WITH_WORKING_MODE(s) \
{ \
   uint32_t s16; \
   uint32_t temp; \
   s16 = s[0]; \
   MUL31(temp, s[0], 8); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[4], 20); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[10], 21); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[13], 17); \
   ADD31(s16, s16, temp); \
   MUL31(temp, s[15], 15); \
   ADD31(s16, s16, temp); \
   SHIFT496(s, s16); \
}

//Bit-reorganization
#define BIT_REORGANIZATION(x0, x1, x2, x3, s) \
{ \
   x0 = ((s[15] << 1) & 0xFFFF0000) | (s[14] & 0xFFFF); \
   x1 = ((s[11] << 16) & 0xFFFF0000) | ((s[9] >> 15) & 0xFFFF); \
   x2 = ((s[7] << 16) & 0xFFFF0000) | ((s[5] >> 15) & 0xFFFF); \
   x3 = ((s[2] << 16) & 0xFFFF0000) | ((s[0] >> 15) & 0xFFFF); \
}

//S-box S
#define S(x) ((uint32_t) s1[(x) & 0xFF] | \
   ((uint32_t) s0[((x) >> 8) & 0xFF] << 8) | \
   ((uint32_t) s1[((x) >> 16) & 0xFF] << 16) | \
   ((uint32_t) s0[((x) >> 24) & 0xFF] << 24))

//Linear transforms L1 and L2
#define L1(x) ((x) ^ ROL32(x, 2) ^ ROL32(x, 10) ^ ROL32(x, 18) ^ ROL32(x, 24))
#define L2(x) ((x) ^ ROL32(x, 8) ^ ROL32(x, 14) ^ ROL32(x, 22) ^ ROL32(x, 30))

//Nonlinear function F
#define F(w, x0, x1, x2, r1, r2) \
{ \
   uint32_t w1; \
   uint32_t w2; \
   uint32_t temp; \
   w = ((x0) ^ (r1)) + (r2); \
   w1 = (r1) + (x1); \
   w2 = (r2) ^ (x2); \
   temp = (w1 << 16) | (w2 >> 16); \
   temp = L1(temp); \
   r1 = S(temp); \
   temp = (w2 << 16) | (w1 >> 16); \
   temp = L2(temp); \
   r2 = S(temp); \
}

//Key loading (ZUC-128)
#define LOAD1(a, b, c) (((uint32_t) (a) << 23) | \
   ((uint32_t) (b) << 8) | (uint32_t) (c))

//Key loading (ZUC-256)
#define LOAD2(a, b, c, d) (((uint32_t) (a) << 23) | \
   ((uint32_t) ((b) & 0x7F) << 16) | \
   ((uint32_t) (c) << 8) | (uint32_t) (d))

//Constant D (ZUC-128)
static const uint16_t d1[16] =
{
   0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
   0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
};

//Constant D (ZUC-256 with 128-bit IV)
static const uint8_t d2[16] =
{
   0x64, 0x43, 0x7B, 0x2A, 0x11, 0x05, 0x51, 0x42, 0x1A, 0x31, 0x18, 0x66, 0x14, 0x2E, 0x01, 0x5C
};

//Constant D (ZUC-256 with 184-bit IV)
static const uint8_t d3[16] =
{
   0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30
};

//S-box S0
static const uint8_t s0[256] =
{
   0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
   0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90,
   0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC,
   0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38,
   0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B,
   0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C,
   0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD,
   0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8,
   0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56,
   0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE,
   0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D,
   0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23,
   0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1,
   0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F,
   0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
   0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60
};

//S-box S1
static const uint8_t s1[256] =
{
   0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
   0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
   0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
   0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
   0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
   0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
   0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
   0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
   0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
   0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
   0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
   0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
   0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
   0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
   0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
   0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2
};


/**
 * @brief Initialize ZUC context using the supplied key and IV
 * @param[in] context Pointer to the ZUC context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @param[in] iv Pointer to the initialization vector
 * @param[in] ivLen Length of the initialization vector
 * @return Error code
 **/

error_t zucInit(ZucContext *context, const uint8_t *key, size_t keyLen,
   const uint8_t *iv, size_t ivLen)
{
   uint_t i;
   uint32_t w;
   uint32_t x0;
   uint32_t x1;
   uint32_t x2;
   uint32_t x3;

   //Check parameters
   if(context == NULL || key == NULL || iv == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   context->ks = 0;
   context->n = 0;

   //Check the length of the key and IV
   if(keyLen == 16 && ivLen == 16)
   {
      //Load the key, IV and constants into the LFSR (ZUC-128)
      context->s[0] = LOAD1(key[0], d1[0], iv[0]);
      context->s[1] = LOAD1(key[1], d1[1], iv[1]);
      context->s[2] = LOAD1(key[2], d1[2], iv[2]);
      context->s[3] = LOAD1(key[3], d1[3], iv[3]);
      context->s[4] = LOAD1(key[4], d1[4], iv[4]);
      context->s[5] = LOAD1(key[5], d1[5], iv[5]);
      context->s[6] = LOAD1(key[6], d1[6], iv[6]);
      context->s[7] = LOAD1(key[7], d1[7], iv[7]);
      context->s[8] = LOAD1(key[8], d1[8], iv[8]);
      context->s[9] = LOAD1(key[9], d1[9], iv[9]);
      context->s[10] = LOAD1(key[10], d1[10], iv[10]);
      context->s[11] = LOAD1(key[11], d1[11], iv[11]);
      context->s[12] = LOAD1(key[12], d1[12], iv[12]);
      context->s[13] = LOAD1(key[13], d1[13], iv[13]);
      context->s[14] = LOAD1(key[14], d1[14], iv[14]);
      context->s[15] = LOAD1(key[15], d1[15], iv[15]);
   }
   else if(keyLen == 32 && ivLen == 16)
   {
      //Load the key, IV and constants into the LFSR (ZUC-256 with 128-bit IV)
      context->s[0] = LOAD2(key[0], d2[0], key[16], key[24]);
      context->s[1] = LOAD2(key[1], d2[1], key[17], key[25]);
      context->s[2] = LOAD2(key[2], d2[2], key[18], key[26]);
      context->s[3] = LOAD2(key[3], d2[3], key[19], key[27]);
      context->s[4] = LOAD2(key[4], d2[4], key[20], key[28]);
      context->s[5] = LOAD2(key[5], d2[5], key[21], key[29]);
      context->s[6] = LOAD2(key[6], d2[6], key[22], key[30]);
      context->s[7] = LOAD2(key[7], d2[7], iv[0], iv[8]);
      context->s[8] = LOAD2(key[8], d2[8], iv[1], iv[9]);
      context->s[9] = LOAD2(key[9], d2[9], iv[2], iv[10]);
      context->s[10] = LOAD2(key[10], d2[10], iv[3], iv[11]);
      context->s[11] = LOAD2(key[11], d2[11], iv[4], iv[12]);
      context->s[12] = LOAD2(key[12], d2[12], iv[5], iv[13]);
      context->s[13] = LOAD2(key[13], d2[13], iv[6], iv[14]);
      context->s[14] = LOAD2(key[14], d2[14], iv[7], iv[15]);
      context->s[15] = LOAD2(key[15], d2[15], key[23], key[31]);
   }
   else if(keyLen == 32 && ivLen == 25)
   {
      //Load the key, IV and constants into the LFSR (ZUC-256 with 184-bit IV)
      context->s[0] =  LOAD2(key[0], d3[0], key[21], key[16]);
      context->s[1] =  LOAD2(key[1], d3[1], key[22], key[17]);
      context->s[2] =  LOAD2(key[2], d3[2], key[23], key[18]);
      context->s[3] =  LOAD2(key[3], d3[3], key[24], key[19]);
      context->s[4] =  LOAD2(key[4], d3[4], key[25], key[20]);
      context->s[5] =  LOAD2(iv[0], d3[5] | (iv[17] & 0x3F), key[5], key[26]);
      context->s[6] =  LOAD2(iv[1], d3[6] | (iv[18] & 0x3F), key[6], key[27]);
      context->s[7] =  LOAD2(iv[10], d3[7] | (iv[19] & 0x3F), key[7], iv[2]);
      context->s[8] =  LOAD2(key[8], d3[8] | (iv[20] & 0x3F), iv[3], iv[11]);
      context->s[9] =  LOAD2(key[9], d3[9] | (iv[21] & 0x3F), iv[12], iv[4]);
      context->s[10] = LOAD2(iv[5], d3[10] | (iv[22] & 0x3F), key[10], key[28]);
      context->s[11] = LOAD2(key[11], d3[11] | (iv[23] & 0x3F), iv[6], iv[13]);
      context->s[12] = LOAD2(key[12], d3[12] | (iv[24] & 0x3F), iv[7], iv[14]);
      context->s[13] = LOAD2(key[13], d3[13], iv[15], iv[8]);
      context->s[14] = LOAD2(key[14], d3[14] | ((key[31] >> 4) & 0x0F), iv[16], iv[9]);
      context->s[15] = LOAD2(key[15], d3[15] | (key[31] & 0x0F), key[30], key[29]);
   }
   else
   {
      //Report an error
      return ERROR_INVALID_PARAMETER;
   }

   //Set the 32-bit memory cells R1 and R2 to be all 0
   context->r1 = 0;
   context->r2 = 0;

   //Then the cipher runs the following operations 32 times
   for(i = 0; i < 32; i++)
   {
      BIT_REORGANIZATION(x0, x1, x2, x3, context->s);
      F(w, x0, x1, x2, context->r1, context->r2);
      w >>= 1;
      LFSR_WITH_INIT_MODE(context->s, w);
   }

   //After the initialization stage, the algorithm moves into the working
   //stage. At the working stage, the algorithm executes the following
   //operations once, and discards the output w of F
   BIT_REORGANIZATION(x0, x1, x2, x3, context->s);
   F(w, x0, x1, x2, context->r1, context->r2);
   LFSR_WITH_WORKING_MODE(context->s);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Generate key stream
 * @param[in] context Pointer to the ZUC context
 * @param[in] output Pointer to the resulting key stream (optional)
 * @param[in] length Number of 32-bit words to be generate
 **/

void zucGenerateKeyStream(ZucContext *context, uint32_t *output,
   size_t length)
{
   uint_t i;
   uint32_t z;
   uint32_t x0;
   uint32_t x1;
   uint32_t x2;
   uint32_t x3;

   //Produce key stream words
   for(i = 0; i < length; i++)
   {
      //For each iteration, the following operations are executed once, and
      //a 32-bit word Z is produced as an output
      BIT_REORGANIZATION(x0, x1, x2, x3, context->s);
      F(z, x0, x1, x2, context->r1, context->r2);
      z ^= x3;
      LFSR_WITH_WORKING_MODE(context->s);

      //Valid output pointer?
      if(output != NULL)
      {
         output[i] = z;
      }
   }
}


/**
 * @brief Encrypt/decrypt data with the ZUC algorithm
 * @param[in] context Pointer to the ZUC context
 * @param[in] input Pointer to the data to encrypt/decrypt (optional)
 * @param[in] output Pointer to the resulting data (optional)
 * @param[in] length Length of the input data
 **/

void zucCipher(ZucContext *context, const uint8_t *input, uint8_t *output,
   size_t length)
{
   size_t i;

   //Encryption loop
   for(i = 0; i < length; i++)
   {
      //Generate one 32-bit word of key stream when necessary
      if(context->n == 0 || context->n >= 4)
      {
         zucGenerateKeyStream(context, &context->ks, 1);
         context->n = 0;
      }

      //Valid output pointer?
      if(output != NULL)
      {
         //Valid input pointer?
         if(input != NULL)
         {
            //XOR the input data with the key stream
            output[i] = input[i] ^ ((context->ks >> 24) & 0xFF);
         }
         else
         {
            //Output the key stream
            output[i] = (context->ks >> 24) & 0xFF;
         }
      }

      //Get the next byte from the 32-bit word
      context->ks <<= 8;
      context->n++;
   }
}


/**
 * @brief Release ZUC context
 * @param[in] context Pointer to the ZUC context
 **/

void zucDeinit(ZucContext *context)
{
   //Clear ZUC context
   osMemset(context, 0, sizeof(ZucContext));
}

#endif
