/**
 * @file rsa.c
 * @brief RSA public-key cryptography standard
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
#include "debug.h"

//Check crypto library configuration
#if (RSA_SUPPORT == ENABLED)

//PKCS #1 OID (1.2.840.113549.1.1)
const uint8_t PKCS1_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01};
//RSA encryption OID (1.2.840.113549.1.1.1)
const uint8_t RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

//MD2 with RSA encryption OID (1.2.840.113549.1.1.2)
const uint8_t MD2_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02};
//MD5 with RSA encryption OID (1.2.840.113549.1.1.4)
const uint8_t MD5_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04};
//SHA-1 with RSA encryption OID (1.2.840.113549.1.1.5)
const uint8_t SHA1_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};
//SHA-224 with RSA encryption OID (1.2.840.113549.1.1.14)
const uint8_t SHA224_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E};
//SHA-256 with RSA encryption OID (1.2.840.113549.1.1.11)
const uint8_t SHA256_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
//SHA-384 with RSA encryption OID (1.2.840.113549.1.1.12)
const uint8_t SHA384_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
//SHA-512 with RSA encryption OID (1.2.840.113549.1.1.13)
const uint8_t SHA512_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};
//SHA-512/224 with RSA encryption OID (1.2.840.113549.1.1.15)
const uint8_t SHA512_224_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0F};
//SHA-512/256 with RSA encryption OID (1.2.840.113549.1.1.16)
const uint8_t SHA512_256_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x10};

//RSASSA-PKCS1-v1_5 signature with SHA-3-224 OID (2.16.840.1.101.3.4.3.13)
const uint8_t RSASSA_PKCS1_V1_5_WITH_SHA3_224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0D};
//RSASSA-PKCS1-v1_5 signature with SHA-3-256 OID (2.16.840.1.101.3.4.3.14)
const uint8_t RSASSA_PKCS1_V1_5_WITH_SHA3_256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0E};
//RSASSA-PKCS1-v1_5 signature with SHA-3-384 OID (2.16.840.1.101.3.4.3.15)
const uint8_t RSASSA_PKCS1_V1_5_WITH_SHA3_384_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0F};
//RSASSA-PKCS1-v1_5 signature with SHA-3-512 OID (2.16.840.1.101.3.4.3.16)
const uint8_t RSASSA_PKCS1_V1_5_WITH_SHA3_512_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10};

//RSASSA-PSS OID (1.2.840.113549.1.1.10)
const uint8_t RSASSA_PSS_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A};
//RSASSA-PSS-SHAKE128 OID (1.3.6.1.5.5.7.6.30)
const uint8_t RSASSA_PSS_SHAKE128_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1E};
//RSASSA-PSS-SHAKE256 OID (1.3.6.1.5.5.7.6.31)
const uint8_t RSASSA_PSS_SHAKE256_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1F};

//MGF1 OID (1.2.840.113549.1.1.8)
const uint8_t MGF1_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08};


/**
 * @brief Initialize an RSA public key
 * @param[in] key Pointer to the RSA public key to initialize
 **/

void rsaInitPublicKey(RsaPublicKey *key)
{
   //Initialize multiple precision integers
   mpiInit(&key->n);
   mpiInit(&key->e);
}


/**
 * @brief Release an RSA public key
 * @param[in] key Pointer to the RSA public key to free
 **/

void rsaFreePublicKey(RsaPublicKey *key)
{
   //Free multiple precision integers
   mpiFree(&key->n);
   mpiFree(&key->e);
}


/**
 * @brief Initialize an RSA private key
 * @param[in] key Pointer to the RSA private key to initialize
 **/

void rsaInitPrivateKey(RsaPrivateKey *key)
{
   //Initialize multiple precision integers
   mpiInit(&key->n);
   mpiInit(&key->e);
   mpiInit(&key->d);
   mpiInit(&key->p);
   mpiInit(&key->q);
   mpiInit(&key->dp);
   mpiInit(&key->dq);
   mpiInit(&key->qinv);

   //Initialize private key slot
   key->slot = -1;
}


/**
 * @brief Release an RSA private key
 * @param[in] key Pointer to the RSA private key to free
 **/

void rsaFreePrivateKey(RsaPrivateKey *key)
{
   //Free multiple precision integers
   mpiFree(&key->n);
   mpiFree(&key->e);
   mpiFree(&key->d);
   mpiFree(&key->p);
   mpiFree(&key->q);
   mpiFree(&key->dp);
   mpiFree(&key->dq);
   mpiFree(&key->qinv);
}


/**
 * @brief RSA key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] k Required bit length of the modulus n
 * @param[in] e Public exponent (3, 5, 17, 257 or 65537)
 * @param[out] privateKey RSA private key
 * @param[out] publicKey RSA public key
 * @return Error code
 **/

error_t rsaGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   size_t k, uint_t e, RsaPrivateKey *privateKey, RsaPublicKey *publicKey)
{
   error_t error;

   //Generate a private key
   error = rsaGeneratePrivateKey(prngAlgo, prngContext, k, e, privateKey);

   //Check status code
   if(!error)
   {
      //Derive the public key from the private key
      error = rsaGeneratePublicKey(privateKey, publicKey);
   }

   //Return status code
   return error;
}


/**
 * @brief RSA private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] k Required bit length of the modulus n
 * @param[in] e Public exponent (3, 5, 17, 257 or 65537)
 * @param[out] privateKey RSA private key
 * @return Error code
 **/

__weak_func error_t rsaGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   size_t k, uint_t e, RsaPrivateKey *privateKey)
{
   error_t error;
   Mpi t1;
   Mpi t2;
   Mpi phy;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL || privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the modulus
   if(k < 8)
      return ERROR_INVALID_PARAMETER;

   //Check the value of the public exponent
   if(e != 3 && e != 5 && e != 17 && e != 257 && e != 65537)
      return ERROR_INVALID_PARAMETER;

   //Initialize multiple precision integers
   mpiInit(&t1);
   mpiInit(&t2);
   mpiInit(&phy);

   //Save public exponent
   MPI_CHECK(mpiSetValue(&privateKey->e, e));

   //Generate a large random prime p
   do
   {
      do
      {
         //Generate a random number of bit length k/2
         MPI_CHECK(mpiRand(&privateKey->p, k / 2, prngAlgo, prngContext));
         //Set the low bit (this ensures the number is odd)
         MPI_CHECK(mpiSetBitValue(&privateKey->p, 0, 1));
         //Set the two highest bits (this ensures that the high bit of n is also set)
         MPI_CHECK(mpiSetBitValue(&privateKey->p, k / 2 - 1, 1));
         MPI_CHECK(mpiSetBitValue(&privateKey->p, k / 2 - 2, 1));

         //Test whether p is a probable prime
         error = mpiCheckProbablePrime(&privateKey->p);

         //Repeat until an acceptable value is found
      } while(error == ERROR_INVALID_VALUE);

      //Check status code
      MPI_CHECK(error);

      //Compute p mod e
      MPI_CHECK(mpiMod(&t1, &privateKey->p, &privateKey->e));

      //Repeat as long as p mod e = 1
   } while(mpiCompInt(&t1, 1) == 0);

   //Generate a large random prime q
   do
   {
      do
      {
         //Generate random number of bit length k - k/2
         MPI_CHECK(mpiRand(&privateKey->q, k - (k / 2), prngAlgo, prngContext));
         //Set the low bit (this ensures the number is odd)
         MPI_CHECK(mpiSetBitValue(&privateKey->q, 0, 1));
         //Set the two highest bits (this ensures that the high bit of n is also set)
         MPI_CHECK(mpiSetBitValue(&privateKey->q, k - (k / 2) - 1, 1));
         MPI_CHECK(mpiSetBitValue(&privateKey->q, k - (k / 2) - 2, 1));

         //Test whether q is a probable prime
         error = mpiCheckProbablePrime(&privateKey->q);

         //Repeat until an acceptable value is found
      } while(error == ERROR_INVALID_VALUE);

      //Check status code
      MPI_CHECK(error);

      //Compute q mod e
      MPI_CHECK(mpiMod(&t2, &privateKey->q, &privateKey->e));

      //Repeat as long as p mod e = 1
   } while(mpiCompInt(&t2, 1) == 0);

   //Make sure p an q are distinct
   if(mpiComp(&privateKey->p, &privateKey->q) == 0)
   {
      MPI_CHECK(ERROR_FAILURE);
   }

   //If p < q, then swap p and q (this only matters if the CRT form of
   //the private key is used)
   if(mpiComp(&privateKey->p, &privateKey->q) < 0)
   {
      //Swap primes
      mpiCopy(&t1, &privateKey->p);
      mpiCopy(&privateKey->p, &privateKey->q);
      mpiCopy(&privateKey->q, &t1);
   }

   //Compute the modulus n = pq
   MPI_CHECK(mpiMul(&privateKey->n, &privateKey->p, &privateKey->q));

   //Compute phy = (p-1)(q-1)
   MPI_CHECK(mpiSubInt(&t1, &privateKey->p, 1));
   MPI_CHECK(mpiSubInt(&t2, &privateKey->q, 1));
   MPI_CHECK(mpiMul(&phy, &t1, &t2));

   //Compute d = e^-1 mod phy
   MPI_CHECK(mpiInvMod(&privateKey->d, &privateKey->e, &phy));
   //Compute dP = d mod (p-1)
   MPI_CHECK(mpiMod(&privateKey->dp, &privateKey->d, &t1));
   //Compute dQ = d mod (q-1)
   MPI_CHECK(mpiMod(&privateKey->dq, &privateKey->d, &t2));
   //Compute qInv = q^-1 mod p
   MPI_CHECK(mpiInvMod(&privateKey->qinv, &privateKey->q, &privateKey->p));

   //Debug message
   TRACE_DEBUG("RSA private key:\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->e);
   TRACE_DEBUG("  Private exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->d);
   TRACE_DEBUG("  Prime 1:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->p);
   TRACE_DEBUG("  Prime 2:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->q);
   TRACE_DEBUG("  Prime exponent 1:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->dp);
   TRACE_DEBUG("  Prime exponent 2:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->dq);
   TRACE_DEBUG("  Coefficient:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->qinv);

end:
   //Release multiple precision integers
   mpiFree(&t1);
   mpiFree(&t2);
   mpiFree(&phy);

   //Any error to report?
   if(error)
   {
      //Release RSA private key
      rsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
}


/**
 * @brief Derive the public key from an RSA private key
 * @param[in] privateKey RSA private key
 * @param[out] publicKey RSA public key
 * @return Error code
 **/

error_t rsaGeneratePublicKey(const RsaPrivateKey *privateKey,
   RsaPublicKey *publicKey)
{
   error_t error;

   //Check parameters
   if(privateKey == NULL || publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //The public key is (n, e)
   MPI_CHECK(mpiCopy(&publicKey->n, &privateKey->n));
   MPI_CHECK(mpiCopy(&publicKey->e, &privateKey->e));

   //Debug message
   TRACE_DEBUG("RSA public key:\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->e);

end:
   //Any error to report?
   if(error)
   {
      //Release RSA public key
      rsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
}


/**
 * @brief RSAES-PKCS1-v1_5 encryption operation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] key Recipient's RSA public key
 * @param[in] message Message to be encrypted
 * @param[in] messageLen Length of the message to be encrypted
 * @param[out] ciphertext Ciphertext resulting from the encryption operation
 * @param[out] ciphertextLen Length of the resulting ciphertext
 * @return Error code
 **/

error_t rsaesPkcs1v15Encrypt(const PrngAlgo *prngAlgo, void *prngContext,
   const RsaPublicKey *key, const uint8_t *message, size_t messageLen,
   uint8_t *ciphertext, size_t *ciphertextLen)
{
   error_t error;
   uint_t k;
   uint8_t *em;
   Mpi m;
   Mpi c;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL || message == NULL)
      return ERROR_INVALID_PARAMETER;
   if(ciphertext == NULL || ciphertextLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSAES-PKCS1-v1_5 encryption...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Message:\r\n");
   TRACE_DEBUG_ARRAY("    ", message, messageLen);

   //Initialize multiple-precision integers
   mpiInit(&m);
   mpiInit(&c);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);

   //Point to the buffer where the encoded message EM will be formatted
   em = ciphertext;

   //EME-PKCS1-v1_5 encoding
   error = emePkcs1v15Encode(prngAlgo, prngContext, message, messageLen, em, k);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Encoded message:\r\n");
   TRACE_DEBUG_ARRAY("    ", em, k);

   //Start of exception handling block
   do
   {
      //Convert the encoded message EM to an integer message representative m
      error = mpiImport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAEP encryption primitive
      error = rsaep(key, &m, &c);
      //Any error to report?
      if(error)
         break;

      //Convert the ciphertext representative c to a ciphertext of length k octets
      error = mpiExport(&c, ciphertext, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Length of the resulting ciphertext
      *ciphertextLen = k;

      //Debug message
      TRACE_DEBUG("  Ciphertext:\r\n");
      TRACE_DEBUG_ARRAY("    ", ciphertext, *ciphertextLen);

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   mpiFree(&m);
   mpiFree(&c);

   //Return status code
   return error;
}


/**
 * @brief RSAES-PKCS1-v1_5 decryption operation
 * @param[in] key Recipient's RSA private key
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertextLen Length of the ciphertext to be decrypted
 * @param[out] message Output buffer where to store the decrypted message
 * @param[in] messageSize Size of the output buffer
 * @param[out] messageLen Length of the decrypted message
 * @return Error code
 **/

error_t rsaesPkcs1v15Decrypt(const RsaPrivateKey *key,
   const uint8_t *ciphertext, size_t ciphertextLen, uint8_t *message,
   size_t messageSize, size_t *messageLen)
{
   error_t error;
   uint_t k;
   size_t i;
   size_t j;
   size_t n;
   uint8_t b;
   uint32_t a;
   uint32_t badPadding;
   uint32_t badLength;
   Mpi c;
   Mpi m;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   uint8_t *em;
#else
   uint8_t em[RSA_MAX_MODULUS_SIZE / 8];
#endif

   //Check parameters
   if(key == NULL || ciphertext == NULL)
      return ERROR_INVALID_PARAMETER;
   if(message == NULL || messageSize == 0 || messageLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSAES-PKCS1-v1_5 decryption...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Private exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->d);
   TRACE_DEBUG("  Prime 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->p);
   TRACE_DEBUG("  Prime 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->q);
   TRACE_DEBUG("  Prime exponent 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dp);
   TRACE_DEBUG("  Prime exponent 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dq);
   TRACE_DEBUG("  Coefficient:\r\n");
   TRACE_DEBUG_MPI("    ", &key->qinv);
   TRACE_DEBUG("  Ciphertext:\r\n");
   TRACE_DEBUG_ARRAY("    ", ciphertext, ciphertextLen);

   //Initialize multiple-precision integers
   mpiInit(&c);
   mpiInit(&m);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);

   //Check the length of the ciphertext
   if(ciphertextLen != k || ciphertextLen < 11)
      return ERROR_INVALID_LENGTH;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a buffer to store the encoded message EM
   em = cryptoAllocMem(k);
   //Failed to allocate memory?
   if(em == NULL)
      return ERROR_OUT_OF_MEMORY;
#else
   //Check the length of the modulus
   if(k > sizeof(em))
      return ERROR_BUFFER_OVERFLOW;
#endif

   //Start of exception handling block
   do
   {
      //Convert the ciphertext to an integer ciphertext representative c
      error = mpiImport(&c, ciphertext, ciphertextLen, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSADP decryption primitive
      error = rsadp(key, &c, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of
      //length k octets
      error = mpiExport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Encoded message:\r\n");
      TRACE_DEBUG_ARRAY("    ", em, k);

      //EME-PKCS1-v1_5 decoding
      badPadding = emePkcs1v15Decode(em, k, &n);

      //Check whether the output buffer is large enough to hold the decrypted
      //message
      badLength = CRYPTO_TEST_LT_32(messageSize, n);

      //Copy the decrypted message, byte per byte
      for(i = 0; i < messageSize; i++)
      {
         //Read the whole encoded message EM
         for(b = 0, j = 0; j < k; j++)
         {
            //Constant time implementation
            a = CRYPTO_TEST_EQ_32(j, k - n + i);
            b = CRYPTO_SELECT_8(b, em[j], a);
         }

         //Save the value of the current byte
         message[i] = b;
      }

      //Return the length of the decrypted message
      *messageLen = CRYPTO_SELECT_32(n, messageSize, badLength);

      //Check whether the decryption operation is successful
      error = (error_t) CRYPTO_SELECT_32(error, ERROR_BUFFER_OVERFLOW, badLength);
      error = (error_t) CRYPTO_SELECT_32(error, ERROR_DECRYPTION_FAILED, badPadding);

      //Debug message
      TRACE_DEBUG("  Message:\r\n");
      TRACE_DEBUG_ARRAY("    ", message, *messageLen);

      //End of exception handling block
   } while(0);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release the encoded message
   cryptoFreeMem(em);
#endif

   //Release multiple precision integers
   mpiFree(&c);
   mpiFree(&m);

   //Return status code
   return error;
}


/**
 * @brief RSAES-OAEP encryption operation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] key Recipient's RSA public key
 * @param[in] hash Underlying hash function
 * @param[in] label Optional label to be associated with the message
 * @param[in] message Message to be encrypted
 * @param[in] messageLen Length of the message to be encrypted
 * @param[out] ciphertext Ciphertext resulting from the encryption operation
 * @param[out] ciphertextLen Length of the resulting ciphertext
 * @return Error code
 **/

error_t rsaesOaepEncrypt(const PrngAlgo *prngAlgo, void *prngContext,
   const RsaPublicKey *key, const HashAlgo *hash, const char_t *label,
   const uint8_t *message, size_t messageLen, uint8_t *ciphertext,
   size_t *ciphertextLen)
{
   error_t error;
   uint_t k;
   uint8_t *em;
   Mpi m;
   Mpi c;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL || message == NULL)
      return ERROR_INVALID_PARAMETER;
   if(ciphertext == NULL || ciphertextLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSAES-OAEP encryption...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Message:\r\n");
   TRACE_DEBUG_ARRAY("    ", message, messageLen);

   //Initialize multiple-precision integers
   mpiInit(&m);
   mpiInit(&c);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);

   //Make sure the modulus is valid
   if(k == 0)
      return ERROR_INVALID_PARAMETER;

   //Point to the buffer where the encoded message EM will be formatted
   em = ciphertext;

   //EME-OAEP encoding
   error = emeOaepEncode(prngAlgo, prngContext, hash, label, message,
      messageLen, em, k);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Encoded message:\r\n");
   TRACE_DEBUG_ARRAY("    ", em, k);

   //Start of exception handling block
   do
   {
      //Convert the encoded message EM to an integer message representative m
      error = mpiImport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAEP encryption primitive
      error = rsaep(key, &m, &c);
      //Any error to report?
      if(error)
         break;

      //Convert the ciphertext representative c to a ciphertext of length k octets
      error = mpiExport(&c, ciphertext, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Length of the resulting ciphertext
      *ciphertextLen = k;

      //Debug message
      TRACE_DEBUG("  Ciphertext:\r\n");
      TRACE_DEBUG_ARRAY("    ", ciphertext, *ciphertextLen);

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   mpiFree(&m);
   mpiFree(&c);

   //Return status code
   return error;
}


/**
 * @brief RSAES-OAEP decryption operation
 * @param[in] key Recipient's RSA private key
 * @param[in] hash Underlying hash function
 * @param[in] label Optional label to be associated with the message
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertextLen Length of the ciphertext to be decrypted
 * @param[out] message Output buffer where to store the decrypted message
 * @param[in] messageSize Size of the output buffer
 * @param[out] messageLen Length of the decrypted message
 * @return Error code
 **/

error_t rsaesOaepDecrypt(const RsaPrivateKey *key, const HashAlgo *hash,
   const char_t *label, const uint8_t *ciphertext, size_t ciphertextLen,
   uint8_t *message, size_t messageSize, size_t *messageLen)
{
   error_t error;
   uint_t k;
   size_t i;
   size_t j;
   size_t n;
   uint8_t b;
   uint32_t a;
   uint32_t badPadding;
   uint32_t badLength;
   Mpi c;
   Mpi m;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   uint8_t *em;
#else
   uint8_t em[RSA_MAX_MODULUS_SIZE / 8];
#endif

   //Check parameters
   if(key == NULL || ciphertext == NULL)
      return ERROR_INVALID_PARAMETER;
   if(message == NULL || messageSize == 0 || messageLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSAES-OAEP decryption...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Private exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->d);
   TRACE_DEBUG("  Prime 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->p);
   TRACE_DEBUG("  Prime 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->q);
   TRACE_DEBUG("  Prime exponent 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dp);
   TRACE_DEBUG("  Prime exponent 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dq);
   TRACE_DEBUG("  Coefficient:\r\n");
   TRACE_DEBUG_MPI("    ", &key->qinv);
   TRACE_DEBUG("  Ciphertext:\r\n");
   TRACE_DEBUG_ARRAY("    ", ciphertext, ciphertextLen);

   //Initialize multiple-precision integers
   mpiInit(&c);
   mpiInit(&m);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);

   //Check the length of the modulus
   if(k < (2 * hash->digestSize + 2))
      return ERROR_INVALID_PARAMETER;

   //Check the length of the ciphertext
   if(ciphertextLen != k)
      return ERROR_INVALID_LENGTH;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a buffer to store the encoded message EM
   em = cryptoAllocMem(k);
   //Failed to allocate memory?
   if(em == NULL)
      return ERROR_OUT_OF_MEMORY;
#else
   //Check the length of the modulus
   if(k > sizeof(em))
      return ERROR_BUFFER_OVERFLOW;
#endif

   //Start of exception handling block
   do
   {
      //Convert the ciphertext to an integer ciphertext representative c
      error = mpiImport(&c, ciphertext, ciphertextLen, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSADP decryption primitive
      error = rsadp(key, &c, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of
      //length k octets
      error = mpiExport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Encoded message:\r\n");
      TRACE_DEBUG_ARRAY("    ", em, k);

      //EME-OAEP decoding
      badPadding = emeOaepDecode(hash, label, em, k, &n);

      //Check whether the output buffer is large enough to hold the decrypted
      //message
      badLength = CRYPTO_TEST_LT_32(messageSize, n);

      //Copy the decrypted message, byte per byte
      for(i = 0; i < messageSize; i++)
      {
         //Read the whole encoded message EM
         for(b = 0, j = 0; j < k; j++)
         {
            //Constant time implementation
            a = CRYPTO_TEST_EQ_32(j, k - n + i);
            b = CRYPTO_SELECT_8(b, em[j], a);
         }

         //Save the value of the current byte
         message[i] = b;
      }

      //Return the length of the decrypted message
      *messageLen = CRYPTO_SELECT_32(n, messageSize, badLength);

      //Check whether the decryption operation is successful
      error = (error_t) CRYPTO_SELECT_32(error, ERROR_BUFFER_OVERFLOW, badLength);
      error = (error_t) CRYPTO_SELECT_32(error, ERROR_DECRYPTION_FAILED, badPadding);

      //Debug message
      TRACE_DEBUG("  Message:\r\n");
      TRACE_DEBUG_ARRAY("    ", message, *messageLen);

      //End of exception handling block
   } while(0);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release the encoded message
   cryptoFreeMem(em);
#endif

   //Release multiple precision integers
   mpiFree(&c);
   mpiFree(&m);

   //Return status code
   return error;
}


/**
 * @brief RSASSA-PKCS1-v1_5 signature generation operation
 * @param[in] key Signer's RSA private key
 * @param[in] hash Hash function used to digest the message
 * @param[in] digest Digest of the message to be signed
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t rsassaPkcs1v15Sign(const RsaPrivateKey *key, const HashAlgo *hash,
   const uint8_t *digest, uint8_t *signature, size_t *signatureLen)
{
   error_t error;
   uint_t k;
   uint8_t *em;
   Mpi m;
   Mpi s;
   Mpi t;

   //Check parameters
   if(key == NULL || hash == NULL || digest == NULL)
      return ERROR_INVALID_PARAMETER;
   if(signature == NULL || signatureLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSASSA-PKCS1-v1_5 signature generation...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Private exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->d);
   TRACE_DEBUG("  Prime 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->p);
   TRACE_DEBUG("  Prime 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->q);
   TRACE_DEBUG("  Prime exponent 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dp);
   TRACE_DEBUG("  Prime exponent 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dq);
   TRACE_DEBUG("  Coefficient:\r\n");
   TRACE_DEBUG_MPI("    ", &key->qinv);
   TRACE_DEBUG("  Message digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, hash->digestSize);

   //Initialize multiple-precision integers
   mpiInit(&m);
   mpiInit(&s);
   mpiInit(&t);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);
   //Point to the buffer where the encoded message EM will be formatted
   em = signature;

   //Apply the EMSA-PKCS1-v1.5 encoding operation
   error = emsaPkcs1v15Encode(hash, digest, em, k);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Encoded message:\r\n");
   TRACE_DEBUG_ARRAY("    ", em, k);

   //Start of exception handling block
   do
   {
      //Convert the encoded message EM to an integer message representative m
      error = mpiImport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSASP1 signature primitive
      error = rsasp1(key, &m, &s);
      //Any error to report?
      if(error)
         break;

      //When unprotected, RSA-CRT is vulnerable to the Bellcore attack
      if(key->n.size && key->e.size && key->p.size && key->q.size &&
         key->dp.size && key->dq.size && key->qinv.size)
      {
         RsaPublicKey publicKey;

         //The pair of numbers (n, e) form the RSA public key
         publicKey.n = key->n;
         publicKey.e = key->e;

         //Apply the RSAVP1 verification primitive
         error = rsavp1(&publicKey, &s, &t);
         //Any error to report?
         if(error)
            break;

         //Verify the RSA signature in order to protect against RSA-CRT key leak
         if(mpiComp(&t, &m) != 0)
         {
            //A signature fault has been detected
            error = ERROR_FAILURE;
            break;
         }
      }

      //Convert the signature representative s to a signature of length k octets
      error = mpiExport(&s, signature, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Length of the resulting signature
      *signatureLen = k;

      //Debug message
      TRACE_DEBUG("  Signature:\r\n");
      TRACE_DEBUG_ARRAY("    ", signature, *signatureLen);

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   mpiFree(&m);
   mpiFree(&s);
   mpiFree(&t);

   //Return status code
   return error;
}


/**
 * @brief RSASSA-PKCS1-v1_5 signature verification operation
 * @param[in] key Signer's RSA public key
 * @param[in] hash Hash function used to digest the message
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t rsassaPkcs1v15Verify(const RsaPublicKey *key, const HashAlgo *hash,
   const uint8_t *digest, const uint8_t *signature, size_t signatureLen)
{
   error_t error;
   uint_t k;
   Mpi s;
   Mpi m;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   uint8_t *em;
#else
   uint8_t em[RSA_MAX_MODULUS_SIZE / 8];
#endif

   //Check parameters
   if(key == NULL || hash == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSASSA-PKCS1-v1_5 signature verification...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Message digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, hash->digestSize);
   TRACE_DEBUG("  Signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", signature, signatureLen);

   //Initialize multiple-precision integers
   mpiInit(&s);
   mpiInit(&m);

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);

   //Make sure the modulus is valid
   if(k == 0)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the signature
   if(signatureLen != k)
      return ERROR_INVALID_SIGNATURE;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a buffer to store the encoded message EM
   em = cryptoAllocMem(k);
   //Failed to allocate memory?
   if(em == NULL)
      return ERROR_OUT_OF_MEMORY;
#else
   //Check the length of the modulus
   if(k > sizeof(em))
      return ERROR_BUFFER_OVERFLOW;
#endif

   //Start of exception handling block
   do
   {
      //Convert the signature to an integer signature representative s
      error = mpiImport(&s, signature, signatureLen, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAVP1 verification primitive
      error = rsavp1(key, &s, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of
      //length k octets
      error = mpiExport(&m, em, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Encoded message:\r\n");
      TRACE_DEBUG_ARRAY("    ", em, k);

      //Verify the encoded message EM
      error = emsaPkcs1v15Verify(hash, digest, em, k);
      //Any error to report?
      if(error)
      {
         //The signature is not valid
         error = ERROR_INVALID_SIGNATURE;
         break;
      }

      //End of exception handling block
   } while(0);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release the encoded message
   cryptoFreeMem(em);
#endif

   //Release multiple precision integers
   mpiFree(&s);
   mpiFree(&m);

   //Return status code
   return error;
}


/**
 * @brief RSASSA-PSS signature generation operation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] key Signer's RSA private key
 * @param[in] hash Hash function used to digest the message
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] digest Digest of the message to be signed
 * @param[out] signature Resulting signature
 * @param[out] signatureLen Length of the resulting signature
 * @return Error code
 **/

error_t rsassaPssSign(const PrngAlgo *prngAlgo, void *prngContext,
   const RsaPrivateKey *key, const HashAlgo *hash, size_t saltLen,
   const uint8_t *digest, uint8_t *signature, size_t *signatureLen)
{
   error_t error;
   uint_t k;
   uint_t modBits;
   uint8_t *em;
   Mpi m;
   Mpi s;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;
   if(key == NULL || hash == NULL || digest == NULL)
      return ERROR_INVALID_PARAMETER;
   if(signature == NULL || signatureLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSASSA-PSS signature generation...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Private exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->d);
   TRACE_DEBUG("  Prime 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->p);
   TRACE_DEBUG("  Prime 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->q);
   TRACE_DEBUG("  Prime exponent 1:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dp);
   TRACE_DEBUG("  Prime exponent 2:\r\n");
   TRACE_DEBUG_MPI("    ", &key->dq);
   TRACE_DEBUG("  Coefficient:\r\n");
   TRACE_DEBUG_MPI("    ", &key->qinv);
   TRACE_DEBUG("  Message digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, hash->digestSize);

   //Initialize multiple-precision integers
   mpiInit(&m);
   mpiInit(&s);

   //modBits is the length in bits of the modulus n
   modBits = mpiGetBitLength(&key->n);

   //Make sure the modulus is valid
   if(modBits == 0)
      return ERROR_INVALID_PARAMETER;

   //Calculate the length in octets of the modulus n
   k = (modBits + 7) / 8;

   //Point to the buffer where the encoded message EM will be formatted
   em = signature;

   //Apply the EMSA-PSS encoding operation to the message M to produce an
   //encoded message EM of length ceil((modBits - 1) / 8) octets
   error = emsaPssEncode(prngAlgo, prngContext, hash, saltLen, digest,
      em, modBits - 1);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Encoded message:\r\n");
   TRACE_DEBUG_ARRAY("    ", em, (modBits + 6) / 8);

   //Start of exception handling block
   do
   {
      //Convert the encoded message EM to an integer message representative m
      error = mpiImport(&m, em, (modBits + 6) / 8, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSASP1 signature primitive
      error = rsasp1(key, &m, &s);
      //Any error to report?
      if(error)
         break;

      //Convert the signature representative s to a signature of length k octets
      error = mpiExport(&s, signature, k, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Length of the resulting signature
      *signatureLen = k;

      //Debug message
      TRACE_DEBUG("  Signature:\r\n");
      TRACE_DEBUG_ARRAY("    ", signature, *signatureLen);

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   mpiFree(&m);
   mpiFree(&s);

   //Return status code
   return error;
}


/**
 * @brief RSASSA-PSS signature verification operation
 * @param[in] key Signer's RSA public key
 * @param[in] hash Hash function used to digest the message
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature to be verified
 * @return Error code
 **/

error_t rsassaPssVerify(const RsaPublicKey *key, const HashAlgo *hash,
   size_t saltLen, const uint8_t *digest, const uint8_t *signature,
   size_t signatureLen)
{
   error_t error;
   uint_t k;
   uint_t modBits;
   Mpi s;
   Mpi m;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   uint8_t *em;
#else
   uint8_t em[RSA_MAX_MODULUS_SIZE / 8];
#endif

   //Check parameters
   if(key == NULL || hash == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSASSA-PSS signature verification...\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);
   TRACE_DEBUG("  Message digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, hash->digestSize);
   TRACE_DEBUG("  Signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", signature, signatureLen);

   //Initialize multiple-precision integers
   mpiInit(&s);
   mpiInit(&m);

   //modBits is the length in bits of the modulus n
   modBits = mpiGetBitLength(&key->n);

   //Make sure the modulus is valid
   if(modBits == 0)
      return ERROR_INVALID_PARAMETER;

   //Calculate the length in octets of the modulus n
   k = (modBits + 7) / 8;

   //Check the length of the signature
   if(signatureLen != k)
      return ERROR_INVALID_SIGNATURE;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a buffer to store the encoded message EM
   em = cryptoAllocMem(k);
   //Failed to allocate memory?
   if(em == NULL)
      return ERROR_OUT_OF_MEMORY;
#else
   //Check the length of the modulus
   if(k > sizeof(em))
      return ERROR_BUFFER_OVERFLOW;
#endif

   //Start of exception handling block
   do
   {
      //Convert the signature to an integer signature representative s
      error = mpiImport(&s, signature, signatureLen, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAVP1 verification primitive
      error = rsavp1(key, &s, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of
      //length emLen = ceil((modBits - 1) / 8) octets
      error = mpiExport(&m, em, (modBits + 6) / 8, MPI_FORMAT_BIG_ENDIAN);
      //Conversion failed?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Encoded message:\r\n");
      TRACE_DEBUG_ARRAY("    ", em, (modBits + 6) / 8);

      //Apply the EMSA-PSS verification operation to the message M and the
      //encoded message EM to determine whether they are consistent
      error = emsaPssVerify(hash, saltLen, digest, em, modBits - 1);
      //Any error to report?
      if(error)
      {
         //The signature is not valid
         error = ERROR_INVALID_SIGNATURE;
         break;
      }

      //End of exception handling block
   } while(0);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release the encoded message
   cryptoFreeMem(em);
#endif

   //Release multiple precision integers
   mpiFree(&s);
   mpiFree(&m);

   //Return status code
   return error;
}

#endif
