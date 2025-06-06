/**
 * @file ascon_aead128.c
 * @brief Ascon-AEAD128
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
 * Ascon-AEAD128 is a nonce-based authenticated encryption with associated data
 * that provides 128-bit security strength
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "lwc/ascon_aead128.h"
#include "debug.h"

//Check crypto library configuration
#if (ASCON_AEAD128_SUPPORT == ENABLED)


/**
 * @brief Authenticated encryption using Ascon-AEAD128
 * @param[in] k key
 * @param[in] kLen Length of the key
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] p Plaintext to be encrypted
 * @param[out] c Ciphertext resulting from the encryption
 * @param[in] length Total number of data bytes to be encrypted
 * @param[out] t MAC resulting from the encryption process
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t asconAead128Encrypt(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *p, uint8_t *c,
   size_t length, uint8_t *t, size_t tLen)
{
   uint8_t buffer[16];
   AsconState state;

   //Check parameters
   if(k == NULL || n == NULL || t == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ascon-AEAD128.enc takes a 128-bit secret key and a 128-bit nonce as input
   //and outputs a 128-bit authentication tag
   if(kLen != 16 || nLen != 16 || tLen != 16)
      return ERROR_INVALID_LENGTH;

   //Given 128-bit K and 128-bit N, the 320-bit internal state S is initialized
   //as S = IV | K | N
   state.x[0] = 0x808C0001;
   state.x[1] = 0x00001000;
   state.x[2] = LOAD32LE(k);
   state.x[3] = LOAD32LE(k + 4);
   state.x[4] = LOAD32LE(k + 8);
   state.x[5] = LOAD32LE(k + 12);
   state.x[6] = LOAD32LE(n);
   state.x[7] = LOAD32LE(n + 4);
   state.x[8] = LOAD32LE(n + 8);
   state.x[9] = LOAD32LE(n + 12);

   //Next, S is updated using the permutation Ascon-p[12]
   asconP(&state, 12);

   //XOR the secret key K into the last 128 bits of internal state
   state.x[6] ^= LOAD32LE(k);
   state.x[7] ^= LOAD32LE(k + 4);
   state.x[8] ^= LOAD32LE(k + 8);
   state.x[9] ^= LOAD32LE(k + 12);

   //Any associated data?
   if(aLen > 0)
   {
      //When associated data is non-empty, it is parsed into blocks
      while(aLen >= 16)
      {
         //Each associated data block Ai is absorbed into the first 128 bits
         //of state
         state.x[0] ^= LOAD32LE(a);
         state.x[1] ^= LOAD32LE(a + 4);
         state.x[2] ^= LOAD32LE(a + 8);
         state.x[3] ^= LOAD32LE(a + 12);

         //And the permutation Ascon-p[8] is applied to the state
         asconP(&state, 8);

         //Number of remaining data bytes
         aLen -= 16;
         a += 16;
      }

      //The final block Am~ can be empty. It is padded so that |Am| = 128
      osMemset(buffer, 0, 16);
      osMemcpy(buffer, a, aLen);
      buffer[aLen] = 0x01;

      //Absorb the final block Am
      state.x[0] ^= LOAD32LE(buffer);
      state.x[1] ^= LOAD32LE(buffer + 4);
      state.x[2] ^= LOAD32LE(buffer + 8);
      state.x[3] ^= LOAD32LE(buffer + 12);

      //The permutation Ascon-p[8] is applied to the state
      asconP(&state, 8);
   }

   //The final step of processing associated data is to update the state with
   //a constant
   state.x[9] ^= 0x80000000;

   //Plaintext P is parsed into blocks
   while(length >= 16)
   {
      //For each Pi, the state S is updated
      state.x[0] ^= LOAD32LE(p);
      state.x[1] ^= LOAD32LE(p + 4);
      state.x[2] ^= LOAD32LE(p + 8);
      state.x[3] ^= LOAD32LE(p + 12);

      //Generate the corresponding ciphertext block Ci
      STORE32LE(state.x[0], c);
      STORE32LE(state.x[1], c + 4);
      STORE32LE(state.x[2], c + 8);
      STORE32LE(state.x[3], c + 12);

      //The permutation Ascon-p[8] is applied to the state
      asconP(&state, 8);

      //Next block
      length -= 16;
      p += 16;
      c += 16;
   }

   //The final block Pn~ can be empty. It is padded so that |Pn| = 128
   osMemset(buffer, 0, 16);
   osMemcpy(buffer, p, length);
   buffer[length] = 0x01;

   //Update the state for the last block Pn
   state.x[0] ^= LOAD32LE(buffer);
   state.x[1] ^= LOAD32LE(buffer + 4);
   state.x[2] ^= LOAD32LE(buffer + 8);
   state.x[3] ^= LOAD32LE(buffer + 12);

   //Generate the corresponding ciphertext block Cn
   STORE32LE(state.x[0], buffer);
   STORE32LE(state.x[1], buffer + 4);
   STORE32LE(state.x[2], buffer + 8);
   STORE32LE(state.x[3], buffer + 12);

   //The last ciphertext block Cn~ is obtained as Cn~ = S[0:l-1]
   osMemcpy(c, buffer, length);

   //During finalization, the key is first loaded to the state S
   state.x[4] ^= LOAD32LE(k);
   state.x[5] ^= LOAD32LE(k + 4);
   state.x[6] ^= LOAD32LE(k + 8);
   state.x[7] ^= LOAD32LE(k + 12);

   //And the state S is then updated using the permutation Ascon-p[12]
   asconP(&state, 12);

   //Finally, the tag T is generated by XORing the key with the last 128 bits
   //of the state
   state.x[6] ^= LOAD32LE(k);
   STORE32LE(state.x[6], t);
   state.x[7] ^= LOAD32LE(k + 4);
   STORE32LE(state.x[7], t + 4);
   state.x[8] ^= LOAD32LE(k + 8);
   STORE32LE(state.x[8], t + 8);
   state.x[9] ^= LOAD32LE(k + 12);
   STORE32LE(state.x[9], t + 12);

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Authenticated decryption using Ascon-AEAD128
 * @param[in] k key
 * @param[in] kLen Length of the key
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[in] a Additional authenticated data
 * @param[in] aLen Length of the additional data
 * @param[in] c Ciphertext to be decrypted
 * @param[out] p Plaintext resulting from the decryption
 * @param[in] length Total number of data bytes to be decrypted
 * @param[in] t MAC to be verified
 * @param[in] tLen Length of the MAC
 * @return Error code
 **/

error_t asconAead128Decrypt(const uint8_t *k, size_t kLen, const uint8_t *n,
   size_t nLen, const uint8_t *a, size_t aLen, const uint8_t *c, uint8_t *p,
   size_t length, const uint8_t *t, size_t tLen)
{
   size_t i;
   uint8_t mask;
   uint32_t temp1;
   uint32_t temp2;
   uint8_t buffer[16];
   AsconState state;

   //Check parameters
   if(k == NULL || n == NULL || t == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ascon-AEAD128.dec takes a 128-bit secret key, a 128-bit nonce and a
   //128-bit authentication tag as input
   if(kLen != 16 || nLen != 16 || tLen != 16)
      return ERROR_INVALID_LENGTH;

   //Given 128-bit K and 128-bit N, the 320-bit internal state S is initialized
   //as S = IV | K | N
   state.x[0] = 0x808C0001;
   state.x[1] = 0x00001000;
   state.x[2] = LOAD32LE(k);
   state.x[3] = LOAD32LE(k + 4);
   state.x[4] = LOAD32LE(k + 8);
   state.x[5] = LOAD32LE(k + 12);
   state.x[6] = LOAD32LE(n);
   state.x[7] = LOAD32LE(n + 4);
   state.x[8] = LOAD32LE(n + 8);
   state.x[9] = LOAD32LE(n + 12);

   //Next, S is updated using the permutation Ascon-p[12]
   asconP(&state, 12);

   //XOR the secret key K into the last 128 bits of internal state
   state.x[6] ^= LOAD32LE(k);
   state.x[7] ^= LOAD32LE(k + 4);
   state.x[8] ^= LOAD32LE(k + 8);
   state.x[9] ^= LOAD32LE(k + 12);

   //Any associated data?
   if(aLen > 0)
   {
      //When associated data is non-empty, it is parsed into blocks
      while(aLen >= 16)
      {
         //Each associated data block Ai is absorbed into the first 128 bits
         //of state
         state.x[0] ^= LOAD32LE(a);
         state.x[1] ^= LOAD32LE(a + 4);
         state.x[2] ^= LOAD32LE(a + 8);
         state.x[3] ^= LOAD32LE(a + 12);

         //And the permutation Ascon-p[8] is applied to the state
         asconP(&state, 8);

         //Number of remaining data bytes
         aLen -= 16;
         a += 16;
      }

      //The final block Am~ can be empty. It is padded so that |Am| = 128
      osMemset(buffer, 0, 16);
      osMemcpy(buffer, a, aLen);
      buffer[aLen] = 0x01;

      //Absorb the final block Am
      state.x[0] ^= LOAD32LE(buffer);
      state.x[1] ^= LOAD32LE(buffer + 4);
      state.x[2] ^= LOAD32LE(buffer + 8);
      state.x[3] ^= LOAD32LE(buffer + 12);

      //The permutation Ascon-p[8] is applied to the state
      asconP(&state, 8);
   }

   //The final step of processing associated data is to update the state with
   //a constant
   state.x[9] ^= 0x80000000;

   //Ciphertext C is parsed into blocks
   while(length >= 16)
   {
      //The plaintext block Pi is obtained as Pi = S[0:127] + Ci
      temp1 = state.x[0] ^ LOAD32LE(c);
      STORE32LE(temp1, p);
      temp1 = state.x[1] ^ LOAD32LE(c + 4);
      STORE32LE(temp1, p + 4);
      temp1 = state.x[2] ^ LOAD32LE(c + 8);
      STORE32LE(temp1, p + 8);
      temp1 = state.x[3] ^ LOAD32LE(c + 12);
      STORE32LE(temp1, p + 12);

      //Update the state S with Ci
      state.x[0] = LOAD32LE(c);
      state.x[1] = LOAD32LE(c + 4);
      state.x[2] = LOAD32LE(c + 8);
      state.x[3] = LOAD32LE(c + 12);

      //The permutation Ascon-p[8] is applied to the state
      asconP(&state, 8);

      //Next block
      length -= 16;
      c += 16;
      p += 16;
   }

   //Copy S[0:127]
   STORE32LE(state.x[0], buffer);
   STORE32LE(state.x[1], buffer + 4);
   STORE32LE(state.x[2], buffer + 8);
   STORE32LE(state.x[3], buffer + 12);

   //The final block Cn~ can be empty
   osMemcpy(buffer, c, length);
   buffer[length] ^= 0x01;

   //For the last block of the ciphertext Cn~, the following steps are applied
   temp1 = LOAD32LE(buffer);
   temp2 = temp1 ^ state.x[0];
   STORE32LE(temp2, buffer);
   state.x[0] = temp1;
   temp1 = LOAD32LE(buffer + 4);
   temp2 = temp1 ^ state.x[1];
   STORE32LE(temp2, buffer + 4);
   state.x[1] = temp1;
   temp1 = LOAD32LE(buffer + 8);
   temp2 = temp1 ^ state.x[2];
   STORE32LE(temp2, buffer + 8);
   state.x[2] = temp1;
   temp1 = LOAD32LE(buffer + 12);
   temp2 = temp1 ^ state.x[3];
   STORE32LE(temp2, buffer + 12);
   state.x[3] = temp1;

   //Copy the last plaintext block Pn~
   osMemcpy(p, buffer, length);

   //During finalization, the key is first loaded to the state S
   state.x[4] ^= LOAD32LE(k);
   state.x[5] ^= LOAD32LE(k + 4);
   state.x[6] ^= LOAD32LE(k + 8);
   state.x[7] ^= LOAD32LE(k + 12);

   //And the state S is then updated using the permutation Ascon-p[12]
   asconP(&state, 12);

   //Finally, the tag T' is generated by XORing the key with the last 128 bits
   //of the state
   state.x[6] ^= LOAD32LE(k);
   STORE32LE(state.x[6], buffer);
   state.x[7] ^= LOAD32LE(k + 4);
   STORE32LE(state.x[7], buffer + 4);
   state.x[8] ^= LOAD32LE(k + 8);
   STORE32LE(state.x[8], buffer + 8);
   state.x[9] ^= LOAD32LE(k + 12);
   STORE32LE(state.x[9], buffer + 12);

   //As the last step, the computed T' is compared with the input T
   for(mask = 0, i = 0; i < 16; i++)
   {
      mask |= buffer[i] ^ t[i];
   }

   //Return status code
   return (mask == 0) ? NO_ERROR : ERROR_FAILURE;
}

#endif
