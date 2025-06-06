/**
 * @file rsa_misc.c
 * @brief Helper routines for RSA
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
 * RSA is an algorithm for public-key cryptography which is suitable for signing
 * as well as encryption. Refer to the following RFCs for complete details:
 * - RFC 2313: PKCS #1: RSA Encryption Version 1.5
 * - RFC 3447: PKCS #1: RSA Cryptography Specifications Version 2.1
 * - RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkc/rsa.h"
#include "pkc/rsa_misc.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (RSA_SUPPORT == ENABLED)

//Padding string
static const uint8_t padding[] =
{
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/**
 * @brief RSA encryption primitive
 *
 * The RSA encryption primitive produces a ciphertext representative from
 * a message representative under the control of a public key
 *
 * @param[in] key RSA public key
 * @param[in] m Message representative
 * @param[out] c Ciphertext representative
 * @return Error code
 **/

__weak_func error_t rsaep(const RsaPublicKey *key, const Mpi *m, Mpi *c)
{
   //Ensure the RSA public key is valid
   if(!key->n.size || !key->e.size)
      return ERROR_INVALID_PARAMETER;

   //The message representative m shall be between 0 and n - 1
   if(mpiCompInt(m, 0) < 0 || mpiComp(m, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Perform modular exponentiation (c = m ^ e mod n)
   return mpiExpModFast(c, m, &key->e, &key->n);
}


/**
 * @brief RSA decryption primitive
 *
 * The RSA decryption primitive recovers the message representative from
 * the ciphertext representative under the control of a private key
 *
 * @param[in] key RSA private key
 * @param[in] c Ciphertext representative
 * @param[out] m Message representative
 * @return Error code
 **/

__weak_func error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;
   Mpi m1;
   Mpi m2;
   Mpi h;

   //The ciphertext representative c shall be between 0 and n - 1
   if(mpiCompInt(c, 0) < 0 || mpiComp(c, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Initialize multiple-precision integers
   mpiInit(&m1);
   mpiInit(&m2);
   mpiInit(&h);

   //Use the Chinese remainder algorithm?
   if(mpiGetLength(&key->n) > 0 && mpiGetLength(&key->p) > 0 &&
      mpiGetLength(&key->q) > 0 && mpiGetLength(&key->dp) > 0 &&
      mpiGetLength(&key->dq) > 0 && mpiGetLength(&key->qinv) > 0)
   {
      //Compute m1 = c ^ dP mod p
      MPI_CHECK(mpiMod(&m1, c, &key->p));
      MPI_CHECK(mpiExpModRegular(&m1, &m1, &key->dp, &key->p));
      //Compute m2 = c ^ dQ mod q
      MPI_CHECK(mpiMod(&m2, c, &key->q));
      MPI_CHECK(mpiExpModRegular(&m2, &m2, &key->dq, &key->q));
      //Let h = (m1 - m2) * qInv mod p
      MPI_CHECK(mpiSub(&h, &m1, &m2));
      MPI_CHECK(mpiMulMod(&h, &h, &key->qinv, &key->p));
      //Let m = m2 + q * h
      MPI_CHECK(mpiMul(m, &key->q, &h));
      MPI_CHECK(mpiAdd(m, m, &m2));
   }
   //Use modular exponentiation?
   else if(mpiGetLength(&key->n) > 0 && mpiGetLength(&key->d) > 0)
   {
      //Let m = c ^ d mod n
      error = mpiExpModRegular(m, c, &key->d, &key->n);
   }
   //Invalid parameters?
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

end:
   //Free previously allocated memory
   mpiFree(&m1);
   mpiFree(&m2);
   mpiFree(&h);

   //Return status code
   return error;
}


/**
 * @brief RSA signature primitive
 *
 * The RSA signature primitive produces a signature representative from
 * a message representative under the control of a private key
 *
 * @param[in] key RSA private key
 * @param[in] m Message representative
 * @param[out] s Signature representative
 * @return Error code
 **/

error_t rsasp1(const RsaPrivateKey *key, const Mpi *m, Mpi *s)
{
   //RSASP1 primitive is the same as RSADP except for the names of its input
   //and output arguments. They are distinguished as they are intended for
   //different purposes
   return rsadp(key, m, s);
}


/**
 * @brief RSA verification primitive
 *
 * The RSA verification primitive recovers the message representative from
 * the signature representative under the control of a public key
 *
 * @param[in] key RSA public key
 * @param[in] s Signature representative
 * @param[out] m Message representative
 * @return Error code
 **/

error_t rsavp1(const RsaPublicKey *key, const Mpi *s, Mpi *m)
{
   //RSAVP1 primitive is the same as RSAEP except for the names of its input
   //and output arguments. They are distinguished as they are intended for
   //different purposes
   return rsaep(key, s, m);
}


/**
 * @brief EME-PKCS1-v1_5 encoding operation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] message Message to be encrypted
 * @param[in] messageLen Length of the message to be encrypted
 * @param[out] em Encoded message
 * @param[in] k Length of the encoded message
 * @return Error code
 **/

error_t emePkcs1v15Encode(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *message, size_t messageLen, uint8_t *em, size_t k)
{
   error_t error;
   size_t i;
   size_t j;
   size_t n;
   uint8_t *p;

   //Check the length of the message
   if((messageLen + 11) > k)
      return ERROR_INVALID_LENGTH;

   //The leading 0x00 octet ensures that the encoded message, converted to
   //an integer, is less than the modulus
   em[0] = 0x00;
   //For a public-key operation, the block type BT shall be 0x02
   em[1] = 0x02;

   //Point to the buffer where to format the padding string PS
   p = em + 2;
   //Determine the length of the padding string
   n = k - messageLen - 3;

   //Generate an octet string PS of length k - mLen - 3 consisting of
   //pseudo-randomly generated nonzero octets
   while(n > 0)
   {
      //Generate random data
      error = prngAlgo->generate(prngContext, p, n);
      //Any error to report?
      if(error)
         return error;

      //Parse the resulting octet string
      for(i = 0, j = 0; j < n; j++)
      {
         //Strip any byte with a value of zero
         if(p[j] != 0)
         {
            p[i++] = p[j];
         }
      }

      //Advance data pointer
      p += i;
      n -= i;
   }

   //Append a 0x00 octet to the padding string
   *p = 0x00;

   //Copy the message to be encrypted
   osMemcpy(p + 1, message, messageLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EME-PKCS1-v1_5 decoding operation
 * @param[in] em Encoded message
 * @param[in] k Length of the encoded message
 * @param[out] messageLen Length of the decrypted message
 * @return The function returns 0 on success, 1 on failure
 **/

uint32_t emePkcs1v15Decode(uint8_t *em, size_t k, size_t *messageLen)
{
   size_t i;
   size_t m;
   uint32_t c;
   uint32_t bad;

   //Separate the encoded message EM into an octet string PS consisting of
   //nonzero octets and a message M
   for(m = 0, i = 2; i < k; i++)
   {
      //Constant time implementation
      c = CRYPTO_TEST_Z_8(em[i]);
      c &= CRYPTO_TEST_Z_32(m);
      m = CRYPTO_SELECT_32(m, i, c);
   }

   //If the first octet of EM does not have hexadecimal value 0x00, then
   //report a decryption error
   bad = CRYPTO_TEST_NEQ_8(em[0], 0x00);

   //If the second octet of EM does not have hexadecimal value 0x02, then
   //report a decryption error
   bad |= CRYPTO_TEST_NEQ_8(em[1], 0x02);

   //If there is no octet with hexadecimal value 0x00 to separate PS from M,
   //then report a decryption error
   bad |= CRYPTO_TEST_Z_32(m);

   //If the length of PS is less than 8 octets, then report a decryption error
   bad |= CRYPTO_TEST_LT_32(m, 10);

   //Return the length of the decrypted message
   *messageLen = CRYPTO_SELECT_32(k - m - 1, 0, bad);

   //Care must be taken to ensure that an opponent cannot distinguish the
   //different error conditions, whether by error message or timing
   return bad;
}


/**
 * @brief EME-OAEP encoding operation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] hash Underlying hash function
 * @param[in] label Optional label to be associated with the message
 * @param[in] message Message to be encrypted
 * @param[in] messageLen Length of the message to be encrypted
 * @param[out] em Encoded message
 * @param[in] k Length of the encoded message
 * @return Error code
 **/

error_t emeOaepEncode(const PrngAlgo *prngAlgo, void *prngContext,
   const HashAlgo *hash, const char_t *label, const uint8_t *message,
   size_t messageLen, uint8_t *em, size_t k)
{
   error_t error;
   size_t n;
   uint8_t *db;
   uint8_t *seed;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //Check the length of the message
   if(messageLen > (k - 2 * hash->digestSize - 2))
      return ERROR_INVALID_LENGTH;

   //Point to the buffer where to format the seed
   seed = em + 1;
   //Point to the buffer where to format the data block
   db = em + hash->digestSize + 1;

   //Generate a random octet string seed of length hLen
   error = prngAlgo->generate(prngContext, seed, hash->digestSize);
   //Any error to report?
   if(error)
      return error;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //If the label L is not provided, let L be the empty string
   if(label == NULL)
   {
      label = "";
   }

   //Let lHash = Hash(L)
   hash->init(hashContext);
   hash->update(hashContext, label, osStrlen(label));
   hash->final(hashContext, db);

   //The padding string PS consists of k - mLen - 2hLen - 2 zero octets
   n = k - messageLen - 2 * hash->digestSize - 2;
   //Generate the padding string
   osMemset(db + hash->digestSize, 0, n);

   //Concatenate lHash, PS, a single octet with hexadecimal value 0x01, and
   //the message M to form a data block DB of length k - hLen - 1 octets
   db[hash->digestSize + n] = 0x01;
   osMemcpy(db + hash->digestSize + n + 1, message, messageLen);

   //Calculate the length of the data block
   n = k - hash->digestSize - 1;

   //Let maskedDB = DB xor MGF(seed, k - hLen - 1)
   mgf1(hash, hashContext, seed, hash->digestSize, db, n);
   //Let maskedSeed = seed xor MGF(maskedDB, hLen)
   mgf1(hash, hashContext, db, n, seed, hash->digestSize);

   //Concatenate a single octet with hexadecimal value 0x00, maskedSeed, and
   //maskedDB to form an encoded message EM of length k octets
   em[0] = 0x00;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(hashContext);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EME-OAEP decoding operation
 * @param[in] hash Underlying hash function
 * @param[in] label Optional label to be associated with the message
 * @param[in] em Encoded message
 * @param[in] k Length of the encoded message
 * @param[out] messageLen Length of the decrypted message
 * @return The function returns 0 on success, 1 on failure
 **/

uint32_t emeOaepDecode(const HashAlgo *hash, const char_t *label, uint8_t *em,
   size_t k, size_t *messageLen)
{
   size_t i;
   size_t m;
   size_t n;
   uint32_t c;
   uint32_t bad;
   uint8_t *db;
   uint8_t *seed;
   uint8_t lHash[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return TRUE;
#endif

   //If the label L is not provided, let L be the empty string
   if(label == NULL)
   {
      label = "";
   }

   //Let lHash = Hash(L)
   hash->init(hashContext);
   hash->update(hashContext, label, osStrlen(label));
   hash->final(hashContext, lHash);

   //Separate the encoded message EM into a single octet Y, an octet string
   //maskedSeed of length hLen, and an octet string maskedDB of length k - hLen - 1
   seed = em + 1;
   db = em + hash->digestSize + 1;

   //Calculate the length of the data block
   n = k - hash->digestSize - 1;

   //Let seed = maskedSeed xor MGF(maskedDB, hLen)
   mgf1(hash, hashContext, db, n, seed, hash->digestSize);
   //Let DB = maskedDB xor MGF(seed, k - hLen - 1)
   mgf1(hash, hashContext, seed, hash->digestSize, db, n);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(hashContext);
#endif

   //Separate DB into an octet string lHash' of length hLen, a padding string
   //PS consisting of octets with hexadecimal value 0x00, and a message M
   for(m = 0, i = hash->digestSize; i < n; i++)
   {
      //Constant time implementation
      c = CRYPTO_TEST_NZ_8(db[i]);
      c &= CRYPTO_TEST_Z_32(m);
      m = CRYPTO_SELECT_32(m, i, c);
   }

   //Make sure the padding string PS is terminated
   bad = CRYPTO_TEST_Z_32(m);

   //If there is no octet with hexadecimal value 0x01 to separate PS from M,
   //then report a decryption error
   bad |= CRYPTO_TEST_NEQ_8(db[m], 0x01);

   //If lHash does not equal lHash', then report a decryption error
   for(i = 0; i < hash->digestSize; i++)
   {
      bad |= CRYPTO_TEST_NEQ_8(db[i], lHash[i]);
   }

   //If Y is nonzero, then report a decryption error
   bad |= CRYPTO_TEST_NEQ_8(em[0], 0x00);

   //Return the length of the decrypted message
   *messageLen = CRYPTO_SELECT_32(n - m - 1, 0, bad);

   //Care must be taken to ensure that an opponent cannot distinguish the
   //different error conditions, whether by error message or timing
   return bad;
}


/**
 * @brief EMSA-PKCS1-v1_5 encoding operation
 * @param[in] hash Hash function used to digest the message
 * @param[in] digest Digest of the message to be signed
 * @param[out] em Encoded message
 * @param[in] emLen Intended length of the encoded message
 * @return Error code
 **/

error_t emsaPkcs1v15Encode(const HashAlgo *hash,
   const uint8_t *digest, uint8_t *em, size_t emLen)
{
   size_t i;
   size_t n;

   //Check the intended length of the encoded message
   if(emLen < (hash->oidSize + hash->digestSize + 21))
      return ERROR_INVALID_LENGTH;

   //Point to the first byte of the encoded message
   i = 0;

   //The leading 0x00 octet ensures that the encoded message, converted to
   //an integer, is less than the modulus
   em[i++] = 0x00;
   //Block type 0x01 is used for private-key operations
   em[i++] = 0x01;

   //Determine the length of the padding string PS
   n = emLen - hash->oidSize - hash->digestSize - 13;

   //Each byte of PS must be set to 0xFF when the block type is 0x01
   osMemset(em + i, 0xFF, n);
   i += n;

   //Append a 0x00 octet to the padding string
   em[i++] = 0x00;

   //Encode the DigestInfo structure using ASN.1
   em[i++] = (uint8_t) (ASN1_ENCODING_CONSTRUCTED | ASN1_TYPE_SEQUENCE);
   em[i++] = (uint8_t) (hash->oidSize + hash->digestSize + 8);
   em[i++] = (uint8_t) (ASN1_ENCODING_CONSTRUCTED | ASN1_TYPE_SEQUENCE);
   em[i++] = (uint8_t) (hash->oidSize + 4);
   em[i++] = (uint8_t) ASN1_TYPE_OBJECT_IDENTIFIER;
   em[i++] = (uint8_t) hash->oidSize;

   //Copy the hash algorithm OID
   osMemcpy(em + i, hash->oid, hash->oidSize);
   i += hash->oidSize;

   //Encode the rest of the ASN.1 structure
   em[i++] = (uint8_t) ASN1_TYPE_NULL;
   em[i++] = 0;
   em[i++] = (uint8_t) ASN1_TYPE_OCTET_STRING;
   em[i++] = (uint8_t) hash->digestSize;

   //Append the hash value
   osMemcpy(em + i, digest, hash->digestSize);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EMSA-PKCS1-v1_5 verification operation
 * @param[in] hash Hash function
 * @param[in] digest Digest value
 * @param[in] em Encoded message
 * @param[in] emLen Length of the encoded message
 * @return Error code
 **/

error_t emsaPkcs1v15Verify(const HashAlgo *hash, const uint8_t *digest,
   const uint8_t *em, size_t emLen)
{
   size_t i;
   size_t j;
   size_t n;
   uint8_t bad;

   //Check the length of the encoded message
   if(emLen < (hash->oidSize + hash->digestSize + 21))
      return ERROR_INVALID_LENGTH;

   //Point to the first byte of the encoded message
   i = 0;

   //The first octet of EM must have hexadecimal value 0x00
   bad = em[i++];
   //The second octet of EM must have hexadecimal value 0x01
   bad |= em[i++] ^ 0x01;

   //Determine the length of the padding string PS
   n = emLen - hash->oidSize - hash->digestSize - 13;

   //Each byte of PS must be set to 0xFF when the block type is 0x01
   for(j = 0; j < n; j++)
   {
      bad |= em[i++] ^ 0xFF;
   }

   //The padding string must be followed by a 0x00 octet
   bad |= em[i++];

   //Check the ASN.1 syntax of the DigestInfo structure
   bad |= em[i++] ^ (uint8_t) (ASN1_ENCODING_CONSTRUCTED | ASN1_TYPE_SEQUENCE);
   bad |= em[i++] ^ (uint8_t) (hash->oidSize + hash->digestSize + 8);
   bad |= em[i++] ^ (uint8_t) (ASN1_ENCODING_CONSTRUCTED | ASN1_TYPE_SEQUENCE);
   bad |= em[i++] ^ (uint8_t) (hash->oidSize + 4);
   bad |= em[i++] ^ (uint8_t) ASN1_TYPE_OBJECT_IDENTIFIER;
   bad |= em[i++] ^ (uint8_t) hash->oidSize;

   //Verify the hash algorithm OID
   for(j = 0; j < hash->oidSize; j++)
   {
      bad |= em[i++] ^ hash->oid[j];
   }

   //Check the rest of the ASN.1 structure
   bad |= em[i++] ^ (uint8_t) ASN1_TYPE_NULL;
   bad |= em[i++];
   bad |= em[i++] ^ (uint8_t) ASN1_TYPE_OCTET_STRING;
   bad |= em[i++] ^ (uint8_t) hash->digestSize;

   //Recover the underlying hash value, and then compare it to the newly
   //computed hash value
   for(j = 0; j < hash->digestSize; j++)
   {
      bad |= em[i++] ^ digest[j];
   }

   //Verification result
   return (bad != 0) ? ERROR_INCONSISTENT_VALUE : NO_ERROR;
}


/**
 * @brief EMSA-PSS encoding operation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] hash Underlying hash function
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] digest Digest of the message to be signed
 * @param[out] em Encoded message
 * @param[in] emBits Maximal bit length of the integer OS2IP(EM)
 * @return Error code
 **/

error_t emsaPssEncode(const PrngAlgo *prngAlgo, void *prngContext,
   const HashAlgo *hash, size_t saltLen, const uint8_t *digest,
   uint8_t *em, uint_t emBits)
{
   error_t error;
   size_t n;
   size_t emLen;
   uint8_t *db;
   uint8_t *salt;
   uint8_t h[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //The encoded message is an octet string of length emLen = ceil(emBits / 8)
   emLen = (emBits + 7) / 8;

   //If emLen < hLen + sLen + 2, output "encoding error" and stop
   if(emLen < (hash->digestSize + saltLen + 2))
      return ERROR_INVALID_LENGTH;

   //The padding string PS consists of emLen - sLen - hLen - 2 zero octets
   n = emLen - saltLen - hash->digestSize - 2;

   //Point to the buffer where to format the data block DB
   db = em;
   //Point to the buffer where to generate the salt
   salt = db + n + 1;

   //Generate a random octet string salt of length sLen
   error = prngAlgo->generate(prngContext, salt, saltLen);
   //Any error to report?
   if(error)
      return error;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Let H = Hash(00 00 00 00 00 00 00 00 || mHash || salt)
   hash->init(hashContext);
   hash->update(hashContext, padding, sizeof(padding));
   hash->update(hashContext, digest, hash->digestSize);
   hash->update(hashContext, salt, saltLen);
   hash->final(hashContext, h);

   //Let DB = PS || 0x01 || salt
   osMemset(db, 0, n);
   db[n] = 0x01;

   //Calculate the length of the data block
   n += saltLen + 1;

   //Let maskedDB = DB xor MGF(H, emLen - hLen - 1)
   mgf1(hash, hashContext, h, hash->digestSize, db, n);

   //Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB
   //to zero
   db[0] &= 0xFF >> (8 * emLen - emBits);

   //Let EM = maskedDB || H || 0xbc
   osMemcpy(em + n, h, hash->digestSize);
   em[n + hash->digestSize] = 0xBC;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(hashContext);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EMSA-PSS verification operation
 * @param[in] hash Underlying hash function
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] digest Digest of the message to be signed
 * @param[out] em Encoded message
 * @param[in] emBits Maximal bit length of the integer OS2IP(EM)
 * @return Error code
 **/

error_t emsaPssVerify(const HashAlgo *hash, size_t saltLen,
   const uint8_t *digest, uint8_t *em, uint_t emBits)
{
   size_t i;
   size_t n;
   size_t emLen;
   uint8_t bad;
   uint8_t mask;
   uint8_t *h;
   uint8_t *db;
   uint8_t *salt;
   uint8_t h2[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HashContext *hashContext;
#else
   HashContext hashContext[1];
#endif

   //The encoded message is an octet string of length emLen = ceil(emBits / 8)
   emLen = (emBits + 7) / 8;

   //Check the length of the encoded message EM
   if(emLen < (hash->digestSize + saltLen + 2))
      return ERROR_INVALID_LENGTH;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the hash context
   hashContext = cryptoAllocMem(hash->contextSize);
   //Failed to allocate memory?
   if(hashContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //If the rightmost octet of EM does not have hexadecimal value 0xbc, output
   //"inconsistent" and stop
   bad = em[emLen - 1] ^ 0xBC;

   //Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be
   //the next hLen octets
   db = em;
   n = emLen - hash->digestSize - 1;
   h = em + n;

   //Form a mask
   mask = 0xFF >> (8 * emLen - emBits);

   //If the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are
   //not all equal to zero, output "inconsistent" and stop
   bad |= db[0] & ~mask;

   //Let DB = maskedDB xor MGF(H, emLen - hLen - 1)
   mgf1(hash, hashContext, h, hash->digestSize, db, n);

   //Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero
   db[0] &= mask;

   //The padding string PS consists of emLen - sLen - hLen - 2 octets
   n = emLen - hash->digestSize - saltLen - 2;

   //If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero, output
   //"inconsistent" and stop
   for(i = 0; i < n; i++)
   {
      bad |= db[i];
   }

   //If the octet at position emLen - hLen - sLen - 1 does not have hexadecimal
   //value 0x01, output "inconsistent" and stop
   bad |= db[n] ^ 0x01;

   //Let salt be the last sLen octets of DB
   salt = db + n + 1;

   //Let H' = Hash(00 00 00 00 00 00 00 00 || mHash || salt)
   hash->init(hashContext);
   hash->update(hashContext, padding, sizeof(padding));
   hash->update(hashContext, digest, hash->digestSize);
   hash->update(hashContext, salt, saltLen);
   hash->final(hashContext, h2);

   //If H = H', output "consistent". Otherwise, output "inconsistent"
   for(i = 0; i < hash->digestSize; i++)
   {
      bad |= h[i] ^ h2[i];
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release hash context
   cryptoFreeMem(hashContext);
#endif

   //Verification result
   return (bad != 0) ? ERROR_INCONSISTENT_VALUE : NO_ERROR;
}


/**
 * @brief MGF1 mask generation function
 * @param[in] hash Hash function
 * @param[in] hashContext Hash function context
 * @param[in] seed Seed from which the mask is generated
 * @param[in] seedLen Length of the seed in bytes
 * @param[in,out] data Data block to be masked
 * @param[in] dataLen Length of the data block in bytes
 **/

void mgf1(const HashAlgo *hash, HashContext *hashContext, const uint8_t *seed,
   size_t seedLen, uint8_t *data, size_t dataLen)
{
   size_t i;
   size_t n;
   uint32_t counter;
   uint8_t c[4];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //The data is processed block by block
   for(counter = 0; dataLen > 0; counter++)
   {
      //Limit the number of bytes to process at a time
      n = MIN(dataLen, hash->digestSize);

      //Convert counter to an octet string C of length 4 octets
      STORE32BE(counter, c);

      //Calculate Hash(mgfSeed || C)
      hash->init(hashContext);
      hash->update(hashContext, seed, seedLen);
      hash->update(hashContext, c, sizeof(c));
      hash->final(hashContext, digest);

      //Apply the mask
      for(i = 0; i < n; i++)
      {
         data[i] ^= digest[i];
      }

      //Advance data pointer
      data += n;
      dataLen -= n;
   }
}

#endif
