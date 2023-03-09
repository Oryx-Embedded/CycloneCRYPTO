/**
 * @file pkcs5_common.c
 * @brief PKCS #5 common definitions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.2.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkix/pkcs5_common.h"
#include "encoding/oid.h"
#include "cipher/cipher_algorithms.h"
#include "mac/hmac.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS5_SUPPORT == ENABLED)

//PBE with MD2 and DES-CBC OID (1.2.840.113549.1.5.1)
const uint8_t PBE_WITH_MD2_AND_DES_CBC_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x01};
//PBE with MD5 and DES-CBC OID (1.2.840.113549.1.5.3)
const uint8_t PBE_WITH_MD5_AND_DES_CBC_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x03};
//PBE with MD2 and RC2-CBC OID (1.2.840.113549.1.5.4)
const uint8_t PBE_WITH_MD2_AND_RC2_CBC_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x04};
//PBE with MD5 and RC2-CBC OID (1.2.840.113549.1.5.6)
const uint8_t PBE_WITH_MD5_AND_RC2_CBC_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x06};
//PBE with SHA-1 and DES-CBC OID (1.2.840.113549.1.5.10)
const uint8_t PBE_WITH_SHA1_AND_DES_CBC_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0A};
//PBE with SHA-1 and RC2-CBC OID (1.2.840.113549.1.5.11)
const uint8_t PBE_WITH_SHA1_AND_RC2_CBC_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0B};

//PBES2 OID (1.2.840.113549.1.5.13)
const uint8_t PBES2_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D};

//DES-CBC-Pad OID (1.3.14.3.2.7)
const uint8_t DES_CBC_PAD_OID[5] = {0x2B, 0x0E, 0x03, 0x02, 0x07};
//DES-EDE3-CBC-Pad OID (1.2.840.113549.3.7)
const uint8_t DES_EDE3_CBC_PAD_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07};
//AES128-CBC-Pad OID (2.16.840.1.101.3.4.1.2)
const uint8_t AES128_CBC_PAD_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02};
//AES192-CBC-Pad OID (2.16.840.1.101.3.4.1.22)
const uint8_t AES192_CBC_PAD_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16};
//AES256-CBC-Pad OID (2.16.840.1.101.3.4.1.42)
const uint8_t AES256_CBC_PAD_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A};


/**
 * @brief Get the hash algorithm to be used for PBES1 operation
 * @param[in] oid Encryption algorithm identifier
 * @param[in] length Length of the encryption algorithm identifier, in bytes
 * @return Hash algorithm
 **/

const HashAlgo *pkcs5GetPbes1HashAlgo(const uint8_t *oid, size_t length)
{
   const HashAlgo *hashAlgo;

#if (PKCS5_MD2_SUPPORT == ENABLED && MD2_SUPPORT == ENABLED)
   //PBE with MD2 and RC2-CBC?
   if(!oidComp(oid, length, PBE_WITH_MD2_AND_RC2_CBC_OID,
      sizeof(PBE_WITH_MD2_AND_RC2_CBC_OID)))
   {
      hashAlgo = MD2_HASH_ALGO;
   }
   //PBE with MD2 and DES-CBC?
   else if(!oidComp(oid, length, PBE_WITH_MD2_AND_DES_CBC_OID,
      sizeof(PBE_WITH_MD2_AND_DES_CBC_OID)))
   {
      hashAlgo = MD2_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_MD5_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   //PBE with MD5 and RC2-CBC?
   if(!oidComp(oid, length, PBE_WITH_MD5_AND_RC2_CBC_OID,
      sizeof(PBE_WITH_MD5_AND_RC2_CBC_OID)))
   {
      hashAlgo = MD5_HASH_ALGO;
   }
   //PBE with MD5 and DES-CBC?
   else if(!oidComp(oid, length, PBE_WITH_MD5_AND_DES_CBC_OID,
      sizeof(PBE_WITH_MD5_AND_DES_CBC_OID)))
   {
      hashAlgo = MD5_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //PBE with SHA-1 and RC2-CBC?
   if(!oidComp(oid, length, PBE_WITH_SHA1_AND_RC2_CBC_OID,
      sizeof(PBE_WITH_SHA1_AND_RC2_CBC_OID)))
   {
      hashAlgo = SHA1_HASH_ALGO;
   }
   //PBE with SHA-1 and DES-CBC?
   else if(!oidComp(oid, length, PBE_WITH_SHA1_AND_DES_CBC_OID,
      sizeof(PBE_WITH_SHA1_AND_DES_CBC_OID)))
   {
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
   //Unknown encryption algorithm identifier?
   {
      hashAlgo = NULL;
   }

   //Return the hash algorithm that matches the specified OID
   return hashAlgo;
}


/**
 * @brief Get the hash algorithm to be used for PBES2 operation
 * @param[in] oid KDF algorithm identifier
 * @param[in] length Length of the KDF algorithm identifier, in bytes
 * @return Hash algorithm
 **/

const HashAlgo *pkcs5GetPbes2HashAlgo(const uint8_t *oid, size_t length)
{
   const HashAlgo *hashAlgo;

#if (PKCS5_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //HMAC with SHA-1?
   if(!oidComp(oid, length, HMAC_WITH_SHA1_OID, sizeof(HMAC_WITH_SHA1_OID)))
   {
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   //HMAC with SHA-224?
   if(!oidComp(oid, length, HMAC_WITH_SHA224_OID, sizeof(HMAC_WITH_SHA224_OID)))
   {
      hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //HMAC with SHA-256?
   if(!oidComp(oid, length, HMAC_WITH_SHA256_OID, sizeof(HMAC_WITH_SHA256_OID)))
   {
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //HMAC with SHA-384?
   if(!oidComp(oid, length, HMAC_WITH_SHA384_OID, sizeof(HMAC_WITH_SHA384_OID)))
   {
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //HMAC with SHA-512?
   if(!oidComp(oid, length, HMAC_WITH_SHA512_OID, sizeof(HMAC_WITH_SHA512_OID)))
   {
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_SHA512_224_SUPPORT == ENABLED && SHA512_224_SUPPORT == ENABLED)
   //HMAC with SHA-512/224?
   if(!oidComp(oid, length, HMAC_WITH_SHA512_224_OID,
      sizeof(HMAC_WITH_SHA512_224_OID)))
   {
      hashAlgo = SHA512_224_HASH_ALGO;
   }
   else
#endif
#if (PKCS5_SHA512_256_SUPPORT == ENABLED && SHA512_256_SUPPORT == ENABLED)
   //HMAC with SHA-512/256?
   if(!oidComp(oid, length, HMAC_WITH_SHA512_256_OID,
      sizeof(HMAC_WITH_SHA512_256_OID)))
   {
      hashAlgo = SHA512_256_HASH_ALGO;
   }
   else
#endif
   //Unknown KDF algorithm identifier?
   {
      hashAlgo = NULL;
   }

   //Return the hash algorithm that matches the specified OID
   return hashAlgo;
}


/**
 * @brief Get the cipher algorithm to be used for PBES1 operation
 * @param[in] oid Encryption algorithm identifier
 * @param[in] length Length of the encryption algorithm identifier, in bytes
 * @return Cipher algorithm
 **/

const CipherAlgo *pkcs5GetPbes1CipherAlgo(const uint8_t *oid, size_t length)
{
   const CipherAlgo *cipherAlgo;

#if (PKCS5_RC2_SUPPORT == ENABLED && RC2_SUPPORT == ENABLED)
   //PBE with MD2 and RC2-CBC?
   if(!oidComp(oid, length, PBE_WITH_MD2_AND_RC2_CBC_OID,
      sizeof(PBE_WITH_MD2_AND_RC2_CBC_OID)))
   {
      cipherAlgo = RC2_CIPHER_ALGO;
   }
   //PBE with MD5 and RC2-CBC?
   else if(!oidComp(oid, length, PBE_WITH_MD5_AND_RC2_CBC_OID,
      sizeof(PBE_WITH_MD5_AND_RC2_CBC_OID)))
   {
      cipherAlgo = RC2_CIPHER_ALGO;
   }
   //PBE with SHA-1 and RC2-CBC?
   else if(!oidComp(oid, length, PBE_WITH_SHA1_AND_RC2_CBC_OID,
      sizeof(PBE_WITH_SHA1_AND_RC2_CBC_OID)))
   {
      cipherAlgo = RC2_CIPHER_ALGO;
   }
   else
#endif
#if (PKCS5_DES_SUPPORT == ENABLED && DES_SUPPORT == ENABLED)
   //PBE with MD2 and DES-CBC?
   if(!oidComp(oid, length, PBE_WITH_MD2_AND_DES_CBC_OID,
      sizeof(PBE_WITH_MD2_AND_DES_CBC_OID)))
   {
      cipherAlgo = DES_CIPHER_ALGO;
   }
   //PBE with MD5 and DES-CBC?
   else if(!oidComp(oid, length, PBE_WITH_MD5_AND_DES_CBC_OID,
      sizeof(PBE_WITH_MD5_AND_DES_CBC_OID)))
   {
      cipherAlgo = DES_CIPHER_ALGO;
   }
   //PBE with SHA-1 and DES-CBC?
   else if(!oidComp(oid, length, PBE_WITH_SHA1_AND_DES_CBC_OID,
      sizeof(PBE_WITH_SHA1_AND_DES_CBC_OID)))
   {
      cipherAlgo = DES_CIPHER_ALGO;
   }
   else
#endif
   //Unknown encryption algorithm identifier?
   {
      cipherAlgo = NULL;
   }

   //Return the cipher algorithm that matches the specified OID
   return cipherAlgo;
}


/**
 * @brief Get the cipher algorithm to be used for PBES2 operation
 * @param[in] oid Encryption algorithm identifier
 * @param[in] length Length of the encryption algorithm identifier, in bytes
 * @return Cipher algorithm
 **/

const CipherAlgo *pkcs5GetPbes2CipherAlgo(const uint8_t *oid, size_t length)
{
   const CipherAlgo *cipherAlgo;

#if (PKCS5_DES_SUPPORT == ENABLED && DES_SUPPORT == ENABLED)
   //DES-CBC-Pad?
   if(!oidComp(oid, length, DES_CBC_PAD_OID, sizeof(DES_CBC_PAD_OID)))
   {
      cipherAlgo = DES_CIPHER_ALGO;
   }
   else
#endif
#if (PKCS5_3DES_SUPPORT == ENABLED && DES3_SUPPORT == ENABLED)
   //DES-EDE3-CBC-Pad?
   if(!oidComp(oid, length, DES_EDE3_CBC_PAD_OID, sizeof(DES_EDE3_CBC_PAD_OID)))
   {
      cipherAlgo = DES3_CIPHER_ALGO;
   }
   else
#endif
#if (PKCS5_AES_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
   //AES128-CBC-Pad?
   if(!oidComp(oid, length, AES128_CBC_PAD_OID, sizeof(AES128_CBC_PAD_OID)))
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   //AES192-CBC-Pad?
   else if(!oidComp(oid, length, AES192_CBC_PAD_OID, sizeof(AES192_CBC_PAD_OID)))
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   //AES256-CBC-Pad?
   else if(!oidComp(oid, length, AES256_CBC_PAD_OID, sizeof(AES256_CBC_PAD_OID)))
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   else
#endif
   //Unknown encryption algorithm identifier?
   {
      cipherAlgo = NULL;
   }

   //Return the cipher algorithm that matches the specified OID
   return cipherAlgo;
}


/**
 * @brief Get the encryption key length to be used for PBES2 operation
 * @param[in] oid Encryption algorithm identifier
 * @param[in] length Length of the encryption algorithm identifier, in bytes
 * @return Encryption key length
 **/

uint_t pkcs5GetPbes2KeyLength(const uint8_t *oid, size_t length)
{
   uint_t keyLen;

#if (PKCS5_DES_SUPPORT == ENABLED && DES_SUPPORT == ENABLED)
   //DES-CBC-Pad?
   if(!oidComp(oid, length, DES_CBC_PAD_OID, sizeof(DES_CBC_PAD_OID)))
   {
      keyLen = 8;
   }
   else
#endif
#if (PKCS5_3DES_SUPPORT == ENABLED && DES3_SUPPORT == ENABLED)
   //DES-EDE3-CBC-Pad?
   if(!oidComp(oid, length, DES_EDE3_CBC_PAD_OID, sizeof(DES_EDE3_CBC_PAD_OID)))
   {
      keyLen = 24;
   }
   else
#endif
#if (PKCS5_AES_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
   //AES128-CBC-Pad?
   if(!oidComp(oid, length, AES128_CBC_PAD_OID, sizeof(AES128_CBC_PAD_OID)))
   {
      keyLen = 16;
   }
   //AES192-CBC-Pad?
   else if(!oidComp(oid, length, AES192_CBC_PAD_OID, sizeof(AES192_CBC_PAD_OID)))
   {
      keyLen = 24;
   }
   //AES256-CBC-Pad?
   else if(!oidComp(oid, length, AES256_CBC_PAD_OID, sizeof(AES256_CBC_PAD_OID)))
   {
      keyLen = 32;
   }
   else
#endif
   //Unknown encryption algorithm identifier?
   {
      keyLen = 0;
   }

   //Return the encryption key length that matches the specified OID
   return keyLen;
}

#endif
