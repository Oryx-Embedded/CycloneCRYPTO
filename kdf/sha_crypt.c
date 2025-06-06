/**
 * @file sha_crypt.c
 * @brief Unix crypt using SHA-256 and SHA-512
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
#include "kdf/sha_crypt.h"
#include "hash/hash_algorithms.h"

//Check crypto library configuration
#if (SHA_CRYPT_SUPPORT == ENABLED)

//Base64 encoding table
static const char_t base64EncTable[64] =
{
   '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
   'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
   'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
   'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};


/**
 * @brief SHA-crypt algorithm
 * @param[in] hashAlgo Underlying hash function (SHA-256 or SHA-512)
 * @param[in] password NULL-terminated password
 * @param[in] salt NULL-terminated salt string
 * @param[out] output Output string
 * @param[out] outputLen Length of the output string (optional parameter)
 * @return Error code
 **/

error_t shaCrypt(const HashAlgo *hashAlgo, const char_t *password,
   const char_t *salt, char_t *output, size_t *outputLen)
{
   bool_t flag;
   uint_t rounds;
   uint_t i;
   size_t j;
   size_t n;
   char_t *p;
   char_t *prefix;
   size_t saltLen;
   size_t passwordLen;
   uint8_t dp[MAX_HASH_DIGEST_SIZE];
   uint8_t ds[MAX_HASH_DIGEST_SIZE];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[2];
#endif

   //Check parameters
   if(hashAlgo == NULL || password == NULL || salt == NULL || output == NULL)
      return ERROR_INVALID_PARAMETER;

   //SHA-crypt is specified for SHA-256 and SHA-512 only
   if(osStrcmp(hashAlgo->name, "SHA-256") == 0)
   {
      //The magic prefix is $5$ for SHA-256
      prefix = "$5$";
   }
   else if(osStrcmp(hashAlgo->name, "SHA-512") == 0)
   {
      //The magic prefix is $6$ for SHA-256
      prefix = "$6$";
   }
   else
   {
      //The hash algorithm is not supported
      return ERROR_UNSUPPORTED_HASH_ALGO;
   }

   //Skip the salt prefix, if any
   if(osStrncmp(salt, prefix, 3) == 0)
   {
      salt += 3;
   }

   //The rounds=<N> specification is optional
   if(osStrncmp(salt, "rounds=", 7) == 0)
   {
      //The rounds=<N> specification is present in the input salt
      flag = TRUE;

      //N is an unsigned decimal number
      rounds = osStrtoul(salt + 7, &p, 10);

      //A trailing '$' is used to separate the rounds specification from the
      //following text
      if(*p != '$')
         return ERROR_INVALID_SYNTAX;

      //Skip the trailing '$' character
      salt = p + 1;

      //Any selection of N below the minimum will cause the use of 1,000
      //rounds
      rounds = MAX(rounds, SHA_CRYPT_MIN_ROUNDS);

      //A value of 1 billion and higher will cause 999,999,999 rounds to
      //be used
      rounds = MIN(rounds, SHA_CRYPT_MAX_ROUNDS);
   }
   else
   {
      //The rounds=<N> specification is absent
      flag = FALSE;
      //The default number of rounds is 5,000
      rounds = SHA_CRYPT_DEFAULT_ROUNDS;
   }

   //Retrieve the length of the salt string
   saltLen = osStrlen(salt);
   //The salt string can be up to 16 characters
   saltLen = MIN(saltLen, SHA_CRYPT_MAX_SALT_LEN);

   //Retrieve the length of the password string
   passwordLen = osStrlen(password);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash contexts
   hashContext = cryptoAllocMem(2 * sizeof(HashContext));
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Start digest A
   hashAlgo->init(&hashContext[0]);
   //The password string is added to digest A
   hashAlgo->update(&hashContext[0], password, passwordLen);
   //The salt string is added to digest A
   hashAlgo->update(&hashContext[0], salt, saltLen);

   //Start digest B
   hashAlgo->init(&hashContext[1]);
   //Add the password to digest B
   hashAlgo->update(&hashContext[1], password, passwordLen);
   //Add the salt string to digest B
   hashAlgo->update(&hashContext[1], salt, saltLen);
   //Add the password again to digest B
   hashAlgo->update(&hashContext[1], password, passwordLen);
   //Finish digest B
   hashAlgo->final(&hashContext[1], digest);

   //For each block of 64 bytes in the password string, add digest B to digest
   //A. For the remaining N bytes of the password string add the first N bytes
   //of digest B to digest A
   for(j = 0; j < passwordLen; j += n)
   {
      n = MIN(passwordLen - j, hashAlgo->digestSize);
      hashAlgo->update(&hashContext[0], digest, n);
   }

   //Process each bit of the binary representation of the length of the password
   //string up to and including the highest 1-digit, starting from to lowest bit
   //position
   for(n = passwordLen; n > 0; n >>= 1)
   {
      //Check the value of the current bit
      if((n & 1) != 0)
      {
         //For a 1-digit add digest B to digest A
         hashAlgo->update(&hashContext[0], digest, hashAlgo->digestSize);
      }
      else
      {
         //For a 0-digit add the password string
         hashAlgo->update(&hashContext[0], password, passwordLen);
      }
   }

   //Finish digest A
   hashAlgo->final(&hashContext[0], digest);

   //Start digest DP
   hashAlgo->init(&hashContext[1]);

   //Process each byte in the password
   for(j = 0; j < passwordLen; j++)
   {
      //Add the password to digest DP
      hashAlgo->update(&hashContext[1], password, passwordLen);
   }

   //Finish digest DP
   hashAlgo->final(&hashContext[1], dp);

   //Start digest DS
   hashAlgo->init(&hashContext[1]);

   //Repeat the following 16+A[0] times, where A[0] represents the first byte
   //in digest A interpreted as an 8-bit unsigned value
   for(j = 0; j < (digest[0] + 16U); j++)
   {
      //Add the salt to digest DS
      hashAlgo->update(&hashContext[1], salt, saltLen);
   }

   //Finish digest DS
   hashAlgo->final(&hashContext[1], ds);

   //Repeat a loop according to the number specified in the rounds=<N>
   //specification in the salt (or the default value if none is present)
   for(i = 0; i < rounds; i++)
   {
      //Start digest C
      hashAlgo->init(&hashContext[0]);

      //Odd or even round?
      if((i & 1) != 0)
      {
         //For odd round numbers add the byte sequence P to digest C
         for(j = 0; j < passwordLen; j += n)
         {
            //For each block of 32 or 64 bytes of length of the password string
            //the entire digest DP is used. For the remaining N bytes use the
            //first N bytes of digest DP
            n = MIN(passwordLen - j, hashAlgo->digestSize);
            hashAlgo->update(&hashContext[0], dp, n);
         }
      }
      else
      {
         //For even round numbers add digest A/C
         hashAlgo->update(&hashContext[0], digest, hashAlgo->digestSize);
      }

      //Round number not divisible by 3?
      if(i % 3 != 0)
      {
         //For all round numbers not divisible by 3 add the byte sequence S
         for(j = 0; j < saltLen; j += n)
         {
            //For each block of 32 or 64 bytes of length of the salt string the
            //entire digest DS is used. For the remaining N bytes use the first
            //N bytes of digest DS
            n = MIN(saltLen - j, hashAlgo->digestSize);
            hashAlgo->update(&hashContext[0], ds, n);
         }
      }

      //Round number not divisible by 7?
      if(i % 7 != 0)
      {
         //For all round numbers not divisible by 7 add the byte sequence P
         for(j = 0; j < passwordLen; j += n)
         {
            //For each block of 32 or 64 bytes of length of the password string
            //the entire digest DP is used. For the remaining N bytes use the
            //first N bytes of digest DP
            n = MIN(passwordLen - j, hashAlgo->digestSize);
            hashAlgo->update(&hashContext[0], dp, n);
         }
      }

      //Odd or even round?
      if((i & 1) != 0)
      {
         //For odd round numbers add digest A/C
         hashAlgo->update(&hashContext[0], digest, hashAlgo->digestSize);
      }
      else
      {
         //For even round numbers add the byte sequence P
         for(j = 0; j < passwordLen; j += n)
         {
            //For each block of 32 or 64 bytes of length of the password string
            //the entire digest DP is used. For the remaining N bytes use the
            //first N bytes of digest DP
            n = MIN(passwordLen - j, hashAlgo->digestSize);
            hashAlgo->update(&hashContext[0], dp, n);
         }
      }

      //Finish digest C
      hashAlgo->final(&hashContext[0], digest);
   }

   //The output string is an ASCII string that begins with the salt prefix
   n = osSprintf(output, "%s", prefix);

   //Check whether the rounds=<N> specification is present in the input salt
   //string
   if(flag)
   {
      //A trailing '$' is added in this case to separate the rounds
      //specification from the following text
      n += osSprintf(output + n, "rounds=%u$", rounds);
   }

   //The salt string truncated to 16 characters
   saltLen = MIN(saltLen, SHA_CRYPT_MAX_SALT_LEN);

   //Append the salt string
   osStrncpy(output + n, salt, saltLen);
   n += saltLen;

   //Append a '$' character
   output[n++] = '$';

   //Append the base-64 encoded final C digest
   n += shaCryptEncodeBase64(hashAlgo, digest, output + n);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(hashContext);
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
 * @param[in] hashAlgo Underlying hash function (SHA-256 or SHA-512)
 * @param[in] input Input digest to encode
 * @param[out] output NULL-terminated string encoded with base-64 algorithm
 * @return Length of the base-64 string
 **/

size_t shaCryptEncodeBase64(const HashAlgo *hashAlgo, const uint8_t *input,
   uint8_t *output)
{
   uint32_t value;
   uint_t i;
   uint_t j;
   uint_t k;

   //SHA-256 or SHA-512 algorithm?
   if(hashAlgo->digestSize == 32)
   {
      //Encode the SHA-256 digest using base-64
      for(i = 0, j = 0, k = 0; i < 30; i += 3)
      {
         //Extract a group of three bytes from the digest
         value = input[k] << 16;
         value |= input[(k + 10) % 30] << 8;
         value |= input[(k + 20) % 30];

         //Each group produces four characters as output
         output[j++] = base64EncTable[value & 0x3F];
         output[j++] = base64EncTable[(value >> 6) & 0x3F];
         output[j++] = base64EncTable[(value >> 12) & 0x3F];
         output[j++] = base64EncTable[(value >> 18) & 0x3F];

         //Next group
         k = (k + 21) % 30;
      }

      //For the last group there are not enough bytes left in the digest and
      //the value zero is used in its place
      value = input[31] << 8;
      value |= input[30];

      //The last group produces three characters as output
      output[j++] = base64EncTable[value & 0x3F];
      output[j++] = base64EncTable[(value >> 6) & 0x3F];
      output[j++] = base64EncTable[(value >> 12) & 0x3F];
   }
   else
   {
      //Encode the SHA-512 digest using base-64
      for(i = 0, j = 0, k = 0; i < 63; i += 3)
      {
         //Extract a group of three bytes from the digest
         value = input[k] << 16;
         value |= input[(k + 21) % 63] << 8;
         value |= input[(k + 42) % 63];

         //Each group produces four characters as output
         output[j++] = base64EncTable[value & 0x3F];
         output[j++] = base64EncTable[(value >> 6) & 0x3F];
         output[j++] = base64EncTable[(value >> 12) & 0x3F];
         output[j++] = base64EncTable[(value >> 18) & 0x3F];

         //Next group
         k = (k + 22) % 63;
      }

      //For the last group there are not enough bytes left in the digest and
      //the value zero is used in its place
      value = input[63];

      //The last group produces two characters as output
      output[j++] = base64EncTable[value & 0x3F];
      output[j++] = base64EncTable[(value >> 6) & 0x3F];
   }

   //Properly terminate the string with a NULL character
   output[j] = '\0';

   //Return the length of the base-64 string
   return j;
}

#endif

