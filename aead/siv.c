/**
 * @file siv.c
 * @brief Synthetic Initialization Vector (SIV)
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
 * SIV (Synthetic Initialization Vector) is an authenticated encryption
 * algorithm designed to provide nonce misuse resistance. Refer to RFC 5297
 * for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "aead/siv.h"
#include "mac/cmac.h"
#include "cipher_modes/ctr.h"
#include "debug.h"

//Check crypto library configuration
#if (SIV_SUPPORT == ENABLED)


/**
 * @brief Authenticated encryption using SIV
 * @param[in] cipher Cipher algorithm
 * @param[in] k Pointer to the secret key
 * @param[in] kLen Length of the secret key
 * @param[in] ad Vector of associated data
 * @param[in] adLen Number of components in the vector of associated data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] v Synthetic IV (16 bytes)
 * @return Error code
 **/

error_t sivEncrypt(const CipherAlgo *cipher, const uint8_t *k, size_t kLen,
   const DataChunk *ad, uint_t adLen, const uint8_t *p, uint8_t *c,
   size_t length, uint8_t *v)
{
   const uint8_t *k1;
   const uint8_t *k2;
   uint8_t q[16];
   CipherContext cipherContext;

   //Check parameters
   if(cipher == NULL || k == NULL)
      return ERROR_INVALID_PARAMETER;

   //SIV supports only symmetric block ciphers whose block size is 128 bits
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK || cipher->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //SIV takes as input a key K of length 256, 384, or 512 bits
   if(kLen != 32 && kLen != 48 && kLen != 64)
      return ERROR_INVALID_PARAMETER;

   //The number of components in the vector is not greater than 126 (refer to
   //RFC 5297, section 2.6)
   if(adLen > 126)
      return ERROR_INVALID_PARAMETER;

   //The key is split into equal halves. K1 is used for S2V and K2 is used
   //for CTR
   kLen /= 2;
   k1 = k;
   k2 = k + kLen;

   //Compute V = S2V(K1, AD, P)
   s2v(cipher, k1, kLen, ad, adLen, p, length, v);

   //The output of S2V is a synthetic IV that represents the initial counter
   //to CTR
   osMemcpy(q, v, 16);

   //The 31st and 63rd bit (where the rightmost bit is the 0th) of the counter
   //are zeroed out just prior to being used by CTR for optimization purposes
   q[8] &= 0x7F;
   q[12] &= 0x7F;

   //K2 is used for CTR
   cipher->init(&cipherContext, k2, kLen);
   //Encrypt plaintext
   ctrEncrypt(cipher, &cipherContext, 128, q, p, c, length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using SIV
 * @param[in] cipher Cipher algorithm
 * @param[in] k Pointer to the secret key
 * @param[in] kLen Length of the secret key
 * @param[in] ad Vector of associated data
 * @param[in] adLen Number of components in the vector of associated data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] v Synthetic IV (16 bytes)
 * @return Error code
 **/

error_t sivDecrypt(const CipherAlgo *cipher, const uint8_t *k, size_t kLen,
   const DataChunk *ad, uint_t adLen, const uint8_t *c, uint8_t *p,
   size_t length, const uint8_t *v)
{
   size_t i;
   uint8_t mask;
   const uint8_t *k1;
   const uint8_t *k2;
   uint8_t q[16];
   uint8_t t[16];
   CipherContext cipherContext;

   //Check parameters
   if(cipher == NULL || k == NULL)
      return ERROR_INVALID_PARAMETER;

   //SIV supports only symmetric block ciphers whose block size is 128 bits
   if(cipher->type != CIPHER_ALGO_TYPE_BLOCK || cipher->blockSize != 16)
      return ERROR_INVALID_PARAMETER;

   //SIV takes as input a key K of length 256, 384, or 512 bits
   if(kLen != 32 && kLen != 48 && kLen != 64)
      return ERROR_INVALID_PARAMETER;

   //The number of components in the vector is not greater than 126 (refer to
   //RFC 5297, section 2.7)
   if(adLen > 126)
      return ERROR_INVALID_PARAMETER;

   //The key is split into equal halves. K1 is used for S2V and K2 is used
   //for CTR
   kLen /= 2;
   k1 = k;
   k2 = k + kLen;

   //the synthetic IV that represents the initial counter to CTR
   osMemcpy(q, v, 16);

   //The 31st and 63rd bit (where the rightmost bit is the 0th) of the counter
   //are zeroed out just prior to being used by CTR for optimization purposes
   q[8] &= 0x7F;
   q[12] &= 0x7F;

   //K2 is used for CTR
   cipher->init(&cipherContext, k2, kLen);
   //Decrypt ciphertext
   ctrDecrypt(cipher, &cipherContext, 128, q, c, p, length);

   //T = S2V(K1, AD1, ..., ADn, P)
   s2v(cipher, k1, kLen, ad, adLen, p, length, t);

   //The calculated synthetic IV is bitwise compared to the received IV. The
   //message is authenticated if and only if the IVs match
   for(mask = 0, i = 0; i < 16; i++)
   {
      mask |= t[i] ^ v[i];
   }

   //Return status code
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief S2V operation
 * @param[in] cipher Cipher algorithm
 * @param[in] k Pointer to the S2V key
 * @param[in] kLen Length of the S2V key
 * @param[in] ad Vector of associated data
 * @param[in] adLen Number of components in the vector of associated data
 * @param[in] p Payload data
 * @param[in] pLen Length of the payload data
 * @param[out] v synthetic IV
 **/

void s2v(const CipherAlgo *cipher, const uint8_t *k, size_t kLen,
   const DataChunk *ad, uint_t adLen, const uint8_t *p, size_t pLen,
   uint8_t *v)
{
   uint_t i;
   uint8_t d[16];
   uint8_t t[16];
   CmacContext cmacContext;

   //The S2V operation is bootstrapped by performing CMAC on a 128-bit
   //string of zeros
   osMemset(t, 0, 16);

   //Compute D = AES-CMAC(K, <zero>)
   cmacInit(&cmacContext, cipher, k, kLen);
   cmacUpdate(&cmacContext, t, 16);
   cmacFinal(&cmacContext, d, 16);

   //Process the vector of associated data
   for(i = 0; i < adLen; i++)
   {
      //Perform doubling
      cmacMul(d, d, 16, 0x87);

      //Compute AES-CMAC(K, Si)
      cmacReset(&cmacContext);
      cmacUpdate(&cmacContext, ad[i].buffer, ad[i].length);
      cmacFinal(&cmacContext, t, 16);

      //Compute D = dbl(D) xor AES-CMAC(K, Si)
      cmacXorBlock(d, d, t, 16);
   }

   //Initialize CMAC computation
   cmacReset(&cmacContext);

   //If the length of the final string is less than 128 bits, the output of
   //the double/xor chain is doubled once more and it is xored with the final
   //string padded using the padding function pad(X)
   if(pLen < 16)
   {
      //Perform doubling
      cmacMul(t, d, 16, 0x87);

      //Calcuate T = dbl(D) xor pad(Sn)
      cmacXorBlock(t, t, p, pLen);
      t[pLen] ^= 0x80;
   }
   else
   {
      //Update CMAC computation
      cmacUpdate(&cmacContext, p, pLen - 16);

      //Calculate T = Sn xorend D
      cmacXorBlock(t, p + pLen - 16, d, 16);
   }

   //That result is input to a final CMAC operation to produce the output V
   cmacUpdate(&cmacContext, t, 16);
   cmacFinal(&cmacContext, v, 16);
}

#endif
