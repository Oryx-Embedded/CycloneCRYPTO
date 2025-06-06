/**
 * @file sm4.c
 * @brief SM4 encryption algorithm
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
#include "cipher/sm4.h"

//Check crypto library configuration
#if (SM4_SUPPORT == ENABLED)

//Nonlinear transformation tau
#define TAU(a) ((uint32_t) s[(a) & 0xFF] | \
   ((uint32_t) s[((a) >> 8) & 0xFF] << 8) | \
   ((uint32_t) s[((a) >> 16) & 0xFF] << 16) | \
   ((uint32_t) s[((a) >> 24) & 0xFF] << 24))

//Linear transformations L and L'
#define L(b) ((b) ^ ROL32(b, 2) ^ ROL32(b, 10) ^ ROL32(b, 18) ^ ROL32(b, 24))
#define LP(b) ((b) ^ ROL32(b, 13) ^ ROL32(b, 23))

//Round function F
#define F(x0, x1, x2, x3, rk) \
{ \
   uint32_t temp; \
   temp = (x1) ^ (x2) ^ (x3) ^ (rk); \
   temp = TAU(temp); \
   x0 ^= L(temp); \
}

//Family key FK
static const uint32_t fk[4] =
{
   0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

//Constant key CK
static const uint32_t ck[32] =
{
   0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
   0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
   0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
   0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

//S-box S
static const uint8_t s[256] =
{
   0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
   0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
   0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
   0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
   0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
   0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
   0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
   0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
   0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
   0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
   0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
   0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
   0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
   0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
   0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
   0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

//SM4-ECB OID (1.2.156.10197.1.104.1)
const uint8_t SM4_ECB_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x01};
//SM4-CBC OID (1.2.156.10197.1.104.2)
const uint8_t SM4_CBC_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x02};
//SM4-OFB OID (1.2.156.10197.1.104.3)
const uint8_t SM4_OFB_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x03};
//SM4-CFB OID (1.2.156.10197.1.104.4)
const uint8_t SM4_CFB_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x04};
//SM4-CTR OID (1.2.156.10197.1.104.7)
const uint8_t SM4_CTR_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x07};
//SM4-GCM OID (1.2.156.10197.1.104.8)
const uint8_t SM4_GCM_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x08};
//SM4-CCM OID (1.2.156.10197.1.104.9)
const uint8_t SM4_CCM_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x09};
//SM4-XTS OID (1.2.156.10197.1.104.10)
const uint8_t SM4_XTS_OID[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x68, 0x0A};

//Common interface for encryption algorithms
const CipherAlgo sm4CipherAlgo =
{
   "SM4",
   sizeof(Sm4Context),
   CIPHER_ALGO_TYPE_BLOCK,
   SM4_BLOCK_SIZE,
   (CipherAlgoInit) sm4Init,
   NULL,
   NULL,
   (CipherAlgoEncryptBlock) sm4EncryptBlock,
   (CipherAlgoDecryptBlock) sm4DecryptBlock,
   (CipherAlgoDeinit) sm4Deinit
};


/**
 * @brief Key expansion
 * @param[in] context Pointer to the SM4 context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

__weak_func error_t sm4Init(Sm4Context *context, const uint8_t *key,
   size_t keyLen)
{
   uint_t i;
   uint32_t temp;
   uint32_t k[4];

   //Check parameters
   if(context == NULL || key == NULL)
      return ERROR_INVALID_PARAMETER;

   //The SM4 encryption key is 128 bits long
   if(keyLen != 16)
      return ERROR_INVALID_KEY_LENGTH;

   //The family key is used for key expansion
   k[0] = LOAD32BE(key) ^ fk[0];
   k[1] = LOAD32BE(key + 4) ^ fk[1];
   k[2] = LOAD32BE(key + 8) ^ fk[2];
   k[3] = LOAD32BE(key + 12) ^ fk[3];

   //Generate round keys
   for(i = 0; i < 32; i++)
   {
      temp = k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ ck[i];
      temp = TAU(temp);
      k[i % 4] ^= LP(temp);
      context->rk[i] = k[i % 4];
   }

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using SM4 algorithm
 * @param[in] context Pointer to the SM4 context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

__weak_func void sm4EncryptBlock(Sm4Context *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t x0;
   uint32_t x1;
   uint32_t x2;
   uint32_t x3;

   //The 16 bytes of plaintext are split into 4 words
   x0 = LOAD32BE(input);
   x1 = LOAD32BE(input + 4);
   x2 = LOAD32BE(input + 8);
   x3 = LOAD32BE(input + 12);

   //Encryption use 32 rounds of a nonlinear key schedule per block
   for(i = 0; i < 32; i += 4)
   {
      F(x0, x1, x2, x3, context->rk[i]);
      F(x1, x0, x2, x3, context->rk[i + 1]);
      F(x2, x0, x1, x3, context->rk[i + 2]);
      F(x3, x0, x1, x2, context->rk[i + 3]);
   }

   //The 4 words of ciphertext are then written as 16 bytes
   STORE32BE(x3, output);
   STORE32BE(x2, output + 4);
   STORE32BE(x1, output + 8);
   STORE32BE(x0, output + 12);
}


/**
 * @brief Decrypt a 16-byte block using SM4 algorithm
 * @param[in] context Pointer to the SM4 context
 * @param[in] input Ciphertext block to decrypt
 * @param[out] output Plaintext block resulting from decryption
 **/

__weak_func void sm4DecryptBlock(Sm4Context *context, const uint8_t *input,
   uint8_t *output)
{
   uint_t i;
   uint32_t x0;
   uint32_t x1;
   uint32_t x2;
   uint32_t x3;

   //The 16 bytes of ciphertext are split into 4 words
   x0 = LOAD32BE(input);
   x1 = LOAD32BE(input + 4);
   x2 = LOAD32BE(input + 8);
   x3 = LOAD32BE(input + 12);

   //The structure of encryption and decryption are identical, except that
   //the round key schedule has its order reversed during decryption
   for(i = 32; i > 0; i -= 4)
   {
      F(x0, x1, x2, x3, context->rk[i - 1]);
      F(x1, x0, x2, x3, context->rk[i - 2]);
      F(x2, x0, x1, x3, context->rk[i - 3]);
      F(x3, x0, x1, x2, context->rk[i - 4]);
   }

   //The 4 words of plaintext are then written as 16 bytes
   STORE32BE(x3, output);
   STORE32BE(x2, output + 4);
   STORE32BE(x1, output + 8);
   STORE32BE(x0, output + 12);
}


/**
 * @brief Release SM4 context
 * @param[in] context Pointer to the SM4 context
 **/

__weak_func void sm4Deinit(Sm4Context *context)
{
   //Clear SM4 context
   osMemset(context, 0, sizeof(Sm4Context));
}

#endif
