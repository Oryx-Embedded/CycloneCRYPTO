/**
 * @file md5_crypt.c
 * @brief Unix crypt using MD5
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
#include "kdf/md5_crypt.h"
#include "hash/md5.h"

//Check crypto library configuration
#if (MD5_CRYPT_SUPPORT == ENABLED)

//Base64 encoding table
static const char_t base64EncTable[64] =
{
   '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
   'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
   'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
   'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};


/**
 * @brief MD5-crypt algorithm
 * @param[in] password NULL-terminated password
 * @param[in] salt NULL-terminated salt string
 * @param[out] output Output string
 * @param[out] outputLen Length of the output string (optional parameter)
 * @return Error code
 **/

error_t md5Crypt(const char_t *password, const char_t *salt, char_t *output,
   size_t *outputLen)
{
   uint_t i;
   size_t j;
   size_t n;
   size_t saltLen;
   size_t passwordLen;
   uint8_t digest[MD5_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Md5Context *md5Context;
#else
   Md5Context md5Context[2];
#endif

   //Check parameters
   if(password == NULL || salt == NULL || output == NULL)
      return ERROR_INVALID_PARAMETER;

   //Skip the salt prefix, if any
   if(osStrncmp(salt, "$1$", 3) == 0)
   {
      salt += 3;
   }

   //Retrieve the length of the salt string
   saltLen = osStrlen(salt);
   //The salt string can be up to 16 characters
   saltLen = MIN(saltLen, MD5_CRYPT_MAX_SALT_LEN);

   //Retrieve the length of the password string
   passwordLen = osStrlen(password);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash contexts
   md5Context = cryptoAllocMem(2 * sizeof(Md5Context));
   //Failed to allocate memory?
   if(md5Context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Start digest A
   md5Init(&md5Context[0]);
   //The password string is added to digest A
   md5Update(&md5Context[0], password, passwordLen);
   //The salt prefix is added to digest A
   md5Update(&md5Context[0], "$1$", 3);
   //The salt string is added to digest A
   md5Update(&md5Context[0], salt, saltLen);

   //Start digest B
   md5Init(&md5Context[1]);
   //Add the password to digest B
   md5Update(&md5Context[1], password, passwordLen);
   //Add the salt string to digest B
   md5Update(&md5Context[1], salt, saltLen);
   //Add the password again to digest B
   md5Update(&md5Context[1], password, passwordLen);
   //Finish digest B
   md5Final(&md5Context[1], digest);

   //For each block of 64 bytes in the password string, add digest B to digest
   //A. For the remaining N bytes of the password string add the first N bytes
   //of digest B to digest A
   for(j = 0; j < passwordLen; j += n)
   {
      n = MIN(passwordLen - j, MD5_DIGEST_SIZE);
      md5Update(&md5Context[0], digest, n);
   }

   //Process each bit of the binary representation of the length of the password
   //string up to and including the highest 1-digit, starting from to lowest bit
   //position
   for(n = passwordLen; n > 0; n >>= 1)
   {
      //Check the value of the current bit
      if((n & 1) != 0)
      {
         //For a 1-digit add 0 to digest A
         md5Update(&md5Context[0], "", 1);
      }
      else
      {
         //For a 0-digit add the first character of the key
         md5Update(&md5Context[0], password, 1);
      }
   }

   //Finish digest A
   md5Final(&md5Context[0], digest);

   //Apply 1000 rounds of calculation
   for(i = 0; i < MD5_CRYPT_ROUNDS; i++)
   {
      //Start digest C
      md5Init(&md5Context[0]);

      //Odd or even round?
      if((i & 1) != 0)
      {
         //For odd round numbers add the password
         md5Update(&md5Context[0], password, passwordLen);
      }
      else
      {
         //For even round numbers add the last digest
         md5Update(&md5Context[0], digest, MD5_DIGEST_SIZE);
      }

      //Round number not divisible by 3?
      if(i % 3 != 0)
      {
         //For all round numbers not divisible by 3 add the salt
         md5Update(&md5Context[0], salt, saltLen);
      }

      //Round number not divisible by 7?
      if(i % 7 != 0)
      {
         //For all round numbers not divisible by 7 add the password
         md5Update(&md5Context[0], password, passwordLen);
      }

      //Odd or even round?
      if((i & 1) != 0)
      {
         //For odd round numbers add the last digest
         md5Update(&md5Context[0], digest, MD5_DIGEST_SIZE);
      }
      else
      {
         //For even round numbers add the password
         md5Update(&md5Context[0], password, passwordLen);
      }

      //Finish intermediate digest
      md5Final(&md5Context[0], digest);
   }

   //The output string is an ASCII string that begins with the salt prefix
   osStrcpy(output, "$1$");
   n = 3;

   //The salt string truncated to 16 characters
   saltLen = MIN(saltLen, MD5_CRYPT_MAX_SALT_LEN);

   //Append the salt string
   osStrncpy(output + n, salt, saltLen);
   n += saltLen;

   //Append a '$' character
   output[n++] = '$';

   //Append the base-64 encoded final C digest
   n += md5CryptEncodeBase64(digest, output + n);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(md5Context);
#endif

   //Length of the output string (excluding the terminating NULL)
   if(outputLen != NULL)
   {
      *outputLen = n;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief base-64 encoding algorithm
 * @param[in] input MD5 digest to encode
 * @param[out] output NULL-terminated string encoded with base-64 algorithm
 * @return Length of the base-64 string
 **/

size_t md5CryptEncodeBase64(const uint8_t *input, uint8_t *output)
{
   uint32_t value;
   uint_t i;
   uint_t j;

   //Encode the MD5 digest using base-64
   for(i = 0, j = 0; i < 5; i++)
   {
      //Extract a group of three bytes from the digest
      value = input[i] << 16;
      value |= input[i + 6] << 8;
      value |= (i < 4) ? input[i + 12] : input[5];

      //Each group produces four characters as output
      output[j++] = base64EncTable[value & 0x3F];
      output[j++] = base64EncTable[(value >> 6) & 0x3F];
      output[j++] = base64EncTable[(value >> 12) & 0x3F];
      output[j++] = base64EncTable[(value >> 18) & 0x3F];
   }

   //For the last group there are not enough bytes left in the digest and
   //the value zero is used in its place
   value = input[11];

   //The last group produces two characters as output
   output[j++] = base64EncTable[value & 0x3F];
   output[j++] = base64EncTable[(value >> 6) & 0x3F];

   //Properly terminate the string with a NULL character
   output[j] = '\0';

   //Return the length of the base-64 string
   return j;
}

#endif

