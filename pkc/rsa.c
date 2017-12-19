/**
 * @file rsa.c
 * @brief RSA public-key cryptography standard
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
 * RSA is an algorithm for public-key cryptography which is suitable for signing
 * as well as encryption. Refer to PKCS #1 (RSA Cryptography Standard)
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkc/rsa.h"
#include "mpi/mpi.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (RSA_SUPPORT == ENABLED)

//PKCS #1 OID (1.2.840.113549.1.1)
const uint8_t PKCS1_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01};
//RSA encryption OID (1.2.840.113549.1.1.1)
const uint8_t RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
//MD5 with RSA encryption OID (1.2.840.113549.1.1.4)
const uint8_t MD5_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04};
//SHA-1 with RSA encryption OID (1.2.840.113549.1.1.5)
const uint8_t SHA1_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};
//SHA-256 with RSA encryption OID (1.2.840.113549.1.1.11)
const uint8_t SHA256_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
//SHA-384 with RSA encryption OID (1.2.840.113549.1.1.12)
const uint8_t SHA384_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
//SHA-512 with RSA encryption OID (1.2.840.113549.1.1.13)
const uint8_t SHA512_WITH_RSA_ENCRYPTION_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};
//RSA PKCS #1 v1.5 signature with SHA-3-224 OID (2.16.840.1.101.3.4.3.13)
const uint8_t RSASSA_PKCS1_v1_5_WITH_SHA3_224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0D};
//RSA PKCS #1 v1.5 signature with SHA-3-256 OID (2.16.840.1.101.3.4.3.14)
const uint8_t RSASSA_PKCS1_v1_5_WITH_SHA3_256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0E};
//RSA PKCS #1 v1.5 signature with SHA-3-384 OID (2.16.840.1.101.3.4.3.15)
const uint8_t RSASSA_PKCS1_v1_5_WITH_SHA3_384_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0F};
//RSA PKCS #1 v1.5 signature with SHA-3-512 OID (2.16.840.1.101.3.4.3.16)
const uint8_t RSASSA_PKCS1_v1_5_WITH_SHA3_512_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10};


/**
 * @brief Initialize a RSA public key
 * @param[in] key Pointer to the RSA public key to initialize
 **/

void rsaInitPublicKey(RsaPublicKey *key)
{
   //Initialize multiple precision integers
   mpiInit(&key->n);
   mpiInit(&key->e);
}


/**
 * @brief Release a RSA public key
 * @param[in] key Pointer to the RSA public key to free
 **/

void rsaFreePublicKey(RsaPublicKey *key)
{
   //Free multiple precision integers
   mpiFree(&key->n);
   mpiFree(&key->e);
}


/**
 * @brief Initialize a RSA private key
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
}


/**
 * @brief Release a RSA private key
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

error_t rsaep(const RsaPublicKey *key, const Mpi *m, Mpi *c)
{
   //Ensure the RSA public key is valid
   if(!key->n.size || !key->e.size)
      return ERROR_INVALID_PARAMETER;

   //The message representative m shall be between 0 and n - 1
   if(mpiCompInt(m, 0) < 0 || mpiComp(m, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Perform modular exponentiation (c = m ^ e mod n)
   return mpiExpMod(c, m, &key->e, &key->n);
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

error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
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
   if(key->n.size && key->p.size && key->q.size &&
      key->dp.size && key->dq.size && key->qinv.size)
   {
      //Compute m1 = c ^ dP mod p
      MPI_CHECK(mpiExpMod(&m1, c, &key->dp, &key->p));
      //Compute m2 = c ^ dQ mod q
      MPI_CHECK(mpiExpMod(&m2, c, &key->dq, &key->q));
      //Let h = (m1 - m2) * qInv mod p
      MPI_CHECK(mpiSub(&h, &m1, &m2));
      MPI_CHECK(mpiMulMod(&h, &h, &key->qinv, &key->p));
      //Let m = m2 + q * h
      MPI_CHECK(mpiMul(m, &key->q, &h));
      MPI_CHECK(mpiAdd(m, m, &m2));
   }
   //Use modular exponentiation?
   else if(key->n.size && key->d.size)
   {
      //Let m = c ^ d mod n
      error = mpiExpMod(m, c, &key->d, &key->n);
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
   //RSASP1 primitive is the same as RSADP except for the names of its
   //input and output arguments. They are distinguished as they are
   //intended for different purposes
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
   //RSAVP1 primitive is the same as RSAEP except for the names of its
   //input and output arguments. They are distinguished as they are
   //intended for different purposes
   return rsaep(key, s, m);
}


/**
 * @brief PKCS #1 v1.5 encryption operation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] key Recipient's RSA public key
 * @param[in] message Message to be encrypted
 * @param[in] messageLen Length of the message to be encrypted
 * @param[out] ciphertext Ciphertext resulting from the encryption operation
 * @param[out] ciphertextLen Length of the resulting ciphertext
 * @return Error code
 **/

error_t rsaesPkcs1v15Encrypt(const PrngAlgo *prngAlgo, void *prngContext, const RsaPublicKey *key,
   const uint8_t *message, size_t messageLen, uint8_t *ciphertext, size_t *ciphertextLen)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t k;
   uint_t n;
   uint8_t *p;
   Mpi m;
   Mpi c;

   //Check parameters
   if(key == NULL || message == NULL)
      return ERROR_INVALID_PARAMETER;
   if(ciphertext == NULL || ciphertextLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSA PKCS #1 v1.5 encryption...\r\n");
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

   //Check the length of the message
   if((messageLen + 11) > k)
      return ERROR_INVALID_LENGTH;

   //Point to the buffer where the encoded message EM will be formatted
   p = ciphertext;

   //The leading 0x00 octet ensures that the encoded message,
   //converted to an integer, is less than the modulus
   *(p++) = 0x00;
   //For a public-key operation, the block type BT shall be 0x02
   *(p++) = 0x02;

   //Length of the padding string PS
   n = k - messageLen - 3;

   //Generate the padding string (pseudo-randomly generated non-zero octets)
   while(n > 0)
   {
      //Generate random data
      error = prngAlgo->read(prngContext, p, n);
      //Any error to report?
      if(error)
         return error;

      //Parse the resulting octet string
      for(i = 0, j = 0; j < n; j++)
      {
         //Strip any byte with a value of zero
         if(p[j] != 0)
            p[i++] = p[j];
      }

      //Advance data pointer
      p += i;
      n -= i;
   }

   //Append a 0x00 octet to the padding string
   *(p++) = 0x00;
   //Copy the message to be encrypted
   cryptoMemcpy(p, message, messageLen);

   //Rewind to the beginning of the encoded message
   p = ciphertext;

   //Debug message
   TRACE_DEBUG("  Encoded message\r\n");
   TRACE_DEBUG_ARRAY("    ", p, k);

   //Start of exception handling block
   do
   {
      //Convert the encoded message EM to an integer message representative m
      error = mpiReadRaw(&m, p, k);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAEP encryption primitive
      error = rsaep(key, &m, &c);
      //Any error to report?
      if(error)
         break;

      //Convert the ciphertext representative c to a ciphertext of length k octets
      error = mpiWriteRaw(&c, ciphertext, k);
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
 * @brief PKCS #1 v1.5 decryption operation
 * @param[in] key Recipient's RSA private key
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertextLen Length of the ciphertext to be decrypted
 * @param[out] message Output buffer where to store the decrypted message
 * @param[in] messageSize Size of the output buffer
 * @param[out] messageLen Length of the decrypted message
 * @return Error code
 **/

error_t rsaesPkcs1v15Decrypt(const RsaPrivateKey *key, const uint8_t *ciphertext,
   size_t ciphertextLen, uint8_t *message, size_t messageSize, size_t *messageLen)
{
   error_t error;
   uint_t i;
   uint_t k;
   uint8_t *em;
   Mpi c;
   Mpi m;

   //Check parameters
   if(key == NULL || ciphertext == NULL)
      return ERROR_INVALID_PARAMETER;
   if(message == NULL || messageLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSA PKCS #1 v1.5 decryption...\r\n");
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

   //Allocate a buffer to store the encoded message EM
   em = cryptoAllocMem(k);
   //Failed to allocate memory?
   if(em == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Start of exception handling block
   do
   {
      //Convert the ciphertext to an integer ciphertext representative c
      error = mpiReadRaw(&c, ciphertext, ciphertextLen);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSADP decryption primitive
      error = rsadp(key, &c, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of length k octets
      error = mpiWriteRaw(&m, em, k);
      //Conversion failed?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Encoded message\r\n");
      TRACE_DEBUG_ARRAY("    ", em, k);

      //The first octet of EM must have a value of 0x00
      //and the block type BT shall be 0x02
      if(em[0] != 0x00 || em[1] != 0x02)
      {
         //Report an error
         error = ERROR_UNEXPECTED_VALUE;
         break;
      }

      //An octet with hexadecimal value 0x00 is used to separate PS from M
      for(i = 2; i < k && em[i] != 0x00; i++);

      //Check whether the padding string is valid
      if(i < 10 || i >= k)
      {
         //Report an error
         error = ERROR_INVALID_PADDING;
         break;
      }

      //Ensure that the output buffer is large enough
      if(messageSize < (k - i - 1))
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
         break;
      }

      //Recover the length of the message
      *messageLen = k - i - 1;
      //Copy the message contents
      cryptoMemcpy(message, em + i + 1, *messageLen);

      //Debug message
      TRACE_DEBUG("  Message:\r\n");
      TRACE_DEBUG_ARRAY("    ", message, *messageLen);

      //End of exception handling block
   } while(0);

   //Release multiple precision integers
   mpiFree(&c);
   mpiFree(&m);
   //Free previously allocated memory
   cryptoFreeMem(em);

   //Return status code
   return error;
}


/**
 * @brief PKCS #1 v1.5 signature generation operation
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

   //Check parameters
   if(key == NULL || hash == NULL || digest == NULL)
      return ERROR_INVALID_PARAMETER;
   if(signature == NULL || signatureLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSA PKCS #1 v1.5 signature generation...\r\n");
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

   //Get the length in octets of the modulus n
   k = mpiGetByteLength(&key->n);
   //Point to the buffer where the encoded message EM will be generated
   em = signature;

   //Apply the EMSA-PKCS1-v1.5 encoding operation
   error = emsaPkcs1v15Encode(hash, digest, em, k);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Encoded message\r\n");
   TRACE_DEBUG_ARRAY("    ", em, k);

   //Start of exception handling block
   do
   {
      //Convert the encoded message EM to an integer message representative m
      error = mpiReadRaw(&m, em, k);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSASP1 signature primitive
      error = rsasp1(key, &m, &s);
      //Any error to report?
      if(error)
         break;

      //Convert the signature representative s to a signature of length k octets
      error = mpiWriteRaw(&s, signature, k);
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
 * @brief PKCS #1 v1.5 signature verification operation
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
   uint8_t *em;
   const uint8_t *oid;
   size_t oidLen;
   const uint8_t *d;
   size_t dLen;
   Mpi s;
   Mpi m;

   //Check parameters
   if(key == NULL || hash == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("RSA PKCS #1 v1.5 signature verification...\r\n");
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

   //Check the length of the signature
   if(signatureLen != k)
      return ERROR_INVALID_SIGNATURE;

   //Allocate a memory buffer to hold the encoded message
   em = cryptoAllocMem(k);
   //Failed to allocate memory?
   if(em == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Start of exception handling block
   do
   {
      //Convert the signature to an integer signature representative s
      error = mpiReadRaw(&s, signature, signatureLen);
      //Conversion failed?
      if(error)
         break;

      //Apply the RSAVP1 verification primitive
      error = rsavp1(key, &s, &m);
      //Any error to report?
      if(error)
         break;

      //Convert the message representative m to an encoded message EM of length k octets
      error = mpiWriteRaw(&m, em, k);
      //Conversion failed?
      if(error)
         break;

      //Debug message
      TRACE_DEBUG("  Encoded message\r\n");
      TRACE_DEBUG_ARRAY("    ", em, k);

      //Parse the encoded message EM
      error = emsaPkcs1v15Decode(em, k, &oid, &oidLen, &d, &dLen);
      //Any error to report?
      if(error)
         break;

      //Assume an error...
      error = ERROR_INVALID_SIGNATURE_ALGO;

      //Ensure the hash algorithm identifier matches the OID
      if(oidComp(oid, oidLen, hash->oid, hash->oidSize))
         break;
      //Check the length of the digest
      if(dLen != hash->digestSize)
         break;

      //Compare the message digest
      error = cryptoMemcmp(digest, d, dLen) ? ERROR_INVALID_SIGNATURE : NO_ERROR;

      //End of exception handling block
   } while(0);

   //Release multiple precision integers
   mpiFree(&s);
   mpiFree(&m);
   //Free previously allocated memory
   cryptoFreeMem(em);

   //Return status code
   return error;
}


/**
 * @brief PKCS #1 v1.5 encoding method
 * @param[in] hash Hash function used to digest the message
 * @param[in] digest Digest of the message to be signed
 * @param[out] em Encoded message
 * @param[in] emLen Intended length of the encoded message
 * @return Error code
 **/

error_t emsaPkcs1v15Encode(const HashAlgo *hash,
   const uint8_t *digest, uint8_t *em, size_t emLen)
{
   uint_t i;
   size_t paddingLen;

   //Ensure the length of the digest is valid
   if((hash->oidSize + hash->digestSize + 21) > emLen)
      return ERROR_INVALID_LENGTH;

   //The leading 0x00 octet ensures that the encoded message,
   //converted to an integer, is less than the modulus
   em[0] = 0x00;
   //Block type 0x01 is used for private-key operations
   em[1] = 0x01;

   //Compute the length of the padding string PS
   paddingLen = emLen - hash->oidSize - hash->digestSize - 13;
   //Fill the padding string with 0xFF
   cryptoMemset(em + 2, 0xFF, paddingLen);

   //Point to the byte that follows PS
   i = paddingLen + 2;
   //Append a 0x00 octet to PS
   em[i++] = 0x00;

   //Encode the DigestInfo using ASN.1
   em[i++] = ASN1_ENCODING_CONSTRUCTED | ASN1_TYPE_SEQUENCE;
   em[i++] = (uint8_t) (hash->oidSize + hash->digestSize + 8);
   em[i++] = ASN1_ENCODING_CONSTRUCTED | ASN1_TYPE_SEQUENCE;
   em[i++] = (uint8_t) (hash->oidSize + 4);
   em[i++] = ASN1_TYPE_OBJECT_IDENTIFIER;
   em[i++] = (uint8_t) hash->oidSize;

   //Copy the hash algorithm OID
   cryptoMemcpy(em + i, hash->oid, hash->oidSize);
   i += hash->oidSize;

   //Encode the rest of the ASN.1 structure
   em[i++] = ASN1_TYPE_NULL;
   em[i++] = 0;
   em[i++] = ASN1_TYPE_OCTET_STRING;
   em[i++] = (uint8_t) hash->digestSize;

   //Append the hash value
   cryptoMemcpy(em + i, digest, hash->digestSize);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief PKCS #1 v1.5 decoding method
 * @param[in] em Encoded message
 * @param[in] emLen Length of the encoded message
 * @param[out] oid Hash algorithm OID
 * @param[out] oidLen Length of the hash algorithm OID
 * @param[out] digest Digest value
 * @param[out] digestLen Length of the digest value

 * @return Error code
 **/

error_t emsaPkcs1v15Decode(const uint8_t *em, size_t emLen, const uint8_t **oid,
   size_t *oidLen, const uint8_t **digest, size_t *digestLen)
{
   error_t error;
   uint_t i;
   size_t length;
   const uint8_t *data;
   Asn1Tag tag;

   //Check the length of the encoded message EM
   if(emLen < 11)
      return ERROR_INVALID_LENGTH;

   //The first octet of EM must have a value of 0x00
   if(em[0] != 0x00)
      return ERROR_UNEXPECTED_VALUE;
   //The block type BT shall be 0x01
   if(em[1] != 0x01)
      return ERROR_UNEXPECTED_VALUE;

   //Check the padding string PS
   for(i = 2; i < emLen; i++)
   {
      //A 0x00 octet indicates the end of the padding string
      if(em[i] == 0x00)
         break;
      //Each byte of PS must be set to 0xFF when the block type is 0x01
      if(em[i] != 0xFF)
         return ERROR_INVALID_PADDING;
   }

   //Check whether the padding string is properly terminated
   if(i >= emLen)
      return ERROR_INVALID_PADDING;
   //The length of PS cannot be less than 8 octets
   if(i < 10)
      return ERROR_INVALID_PADDING;

   //Point to the DigestInfo structure
   data = em + i + 1;
   length = emLen - i - 1;

   //Read the contents of the DigestInfo structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode the ASN.1 tag?
   if(error)
      return ERROR_INVALID_TAG;

   //Enforce encoding, class and type
   if(!tag.constructed || tag.objType != ASN1_TYPE_SEQUENCE)
      return ERROR_INVALID_TAG;

   //Point to the DigestAlgorithm structure
   data = tag.value;
   length = tag.length;

   //Decode the DigestAlgorithm tag
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode the ASN.1 tag?
   if(error)
      return ERROR_INVALID_TAG;

   //Enforce encoding, class and type
   if(!tag.constructed || tag.objType != ASN1_TYPE_SEQUENCE)
      return ERROR_INVALID_TAG;

   //Save the location of the next tag
   data += tag.totalLength;
   length -= tag.totalLength;

   //Decode the AlgorithmIdentifier tag
   error = asn1ReadTag(tag.value, tag.length, &tag);
   //Failed to decode the ASN.1 tag?
   if(error)
      return ERROR_INVALID_TAG;

   //Enforce encoding, class and type
   if(tag.constructed || tag.objType != ASN1_TYPE_OBJECT_IDENTIFIER)
      return ERROR_INVALID_TAG;

   //Save the hash algorithm OID
   *oid = tag.value;
   *oidLen = tag.length;

   //Decode the DigestValue tag
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode the ASN.1 tag?
   if(error)
      return ERROR_INVALID_TAG;

   //Enforce encoding, class and type
   if(tag.constructed || tag.objType != ASN1_TYPE_OCTET_STRING)
      return ERROR_INVALID_TAG;

   //Save the hash value
   *digest = tag.value;
   *digestLen = tag.length;

   //EM successfully decoded
   return NO_ERROR;
}

#endif
