/**
 * @file pkcs7_common.c
 * @brief PKCS #7 common definitions
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
#include "pkcs7/pkcs7_common.h"
#include "hash/hash_algorithms.h"
#include "cipher/cipher_algorithms.h"
#include "pkc/rsa.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS7_SUPPORT == ENABLED)

//PKCS #7 OID (1.2.840.113549.1.7)
const uint8_t PKCS7_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07};
//PKCS #7 Data OID (1.2.840.113549.1.7.1)
const uint8_t PKCS7_DATA_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};
//PKCS #7 Signed Data OID (1.2.840.113549.1.7.2)
const uint8_t PKCS7_SIGNED_DATA_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
//PKCS #7 Enveloped Data OID (1.2.840.113549.1.7.3)
const uint8_t PKCS7_ENVELOPED_DATA_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03};
//PKCS #7 Signed And Enveloped Data OID (1.2.840.113549.1.7.4)
const uint8_t PKCS7_SIGNED_AND_ENVELOPED_DATA_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x04};
//PKCS #7 Digested Data OID (1.2.840.113549.1.7.5)
const uint8_t PKCS7_DIGESTED_DATA_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05};
//PKCS #7 Encrypted Data OID (1.2.840.113549.1.7.6)
const uint8_t PKCS7_ENCRYPTED_DATA_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06};

//PKCS #9 Content Type OID (1.2.840.113549.1.9.3)
const uint8_t PKCS9_CONTENT_TYPE_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03};
//PKCS #9 Message Digest OID (1.2.840.113549.1.9.4)
const uint8_t PKCS9_MESSAGE_DIGEST_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04};
//PKCS #9 Signing Time OID (1.2.840.113549.1.9.5)
const uint8_t PKCS9_SIGNING_TIME_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05};


/**
 * @brief Get the hash algorithm that matches the specified OID
 * @param[in] oid Algorithm identifier
 * @param[in] length Length of the algorithm identifier, in bytes
 * @return Hash algorithm
 **/

const HashAlgo *pkcs7GetHashAlgo(const uint8_t *oid, size_t length)
{
   const HashAlgo *hashAlgo;

#if (PKCS7_MD5_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   //MD5 algorithm identifier?
   if(OID_COMP(oid, length, MD5_OID) == 0)
   {
      hashAlgo = MD5_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //SHA-1 algorithm identifier?
   if(OID_COMP(oid, length, SHA1_OID) == 0)
   {
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   //SHA-224 algorithm identifier?
   if(OID_COMP(oid, length, SHA224_OID) == 0)
   {
      hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //SHA-256 algorithm identifier?
   if(OID_COMP(oid, length, SHA256_OID) == 0)
   {
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //SHA-384 algorithm identifier?
   if(OID_COMP(oid, length, SHA384_OID) == 0)
   {
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //SHA-512 algorithm identifier?
   if(OID_COMP(oid, length, SHA512_OID) == 0)
   {
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      hashAlgo = NULL;
   }

   //Return the hash algorithm that matches the specified OID
   return hashAlgo;
}


/**
 * @brief Get the signature hash algorithm that matches the specified OID
 * @param[in] oid Algorithm identifier
 * @param[in] length Length of the algorithm identifier, in bytes
 * @return Hash algorithm
 **/

const HashAlgo *pkcs7GetSignHashAlgo(const uint8_t *oid, size_t length)
{
   const HashAlgo *hashAlgo;

#if (PKCS7_MD5_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   //MD5 algorithm identifier?
   if(OID_COMP(oid, length, MD5_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      hashAlgo = MD5_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //SHA-1 algorithm identifier?
   if(OID_COMP(oid, length, SHA1_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   //SHA-224 algorithm identifier?
   if(OID_COMP(oid, length, SHA224_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //SHA-256 algorithm identifier?
   if(OID_COMP(oid, length, SHA256_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //SHA-384 algorithm identifier?
   if(OID_COMP(oid, length, SHA384_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (PKCS7_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //SHA-512 algorithm identifier?
   if(OID_COMP(oid, length, SHA512_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      hashAlgo = NULL;
   }

   //Return the hash algorithm that matches the specified OID
   return hashAlgo;
}


/**
 * @brief Get the cipher algorithm that matches the specified OID
 * @param[in] oid Algorithm identifier
 * @param[in] length Length of the algorithm identifier, in bytes
 * @return Cipher algorithm
 **/

const CipherAlgo *pkcs7GetCipherAlgo(const uint8_t *oid, size_t length)
{
   const CipherAlgo *cipherAlgo;

#if (PKCS7_DES_SUPPORT == ENABLED && DES_SUPPORT == ENABLED)
   //DES-CBC algorithm identifier?
   if(OID_COMP(oid, length, DES_CBC_OID) == 0)
   {
      cipherAlgo = DES_CIPHER_ALGO;
   }
   else
#endif
#if (PKCS7_3DES_SUPPORT == ENABLED && DES3_SUPPORT == ENABLED)
   //DES-EDE3-CBC algorithm identifier?
   if(OID_COMP(oid, length, DES_EDE3_CBC_OID) == 0)
   {
      cipherAlgo = DES3_CIPHER_ALGO;
   }
   else
#endif
#if (PKCS7_AES_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
   //AES128-CBC algorithm identifier?
   if(OID_COMP(oid, length, AES128_CBC_OID) == 0)
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   //AES192-CBC algorithm identifier?
   else if(OID_COMP(oid, length, AES192_CBC_OID) == 0)
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   //AES256-CBC algorithm identifier?
   else if(OID_COMP(oid, length, AES256_CBC_OID) == 0)
   {
      cipherAlgo = AES_CIPHER_ALGO;
   }
   else
#endif
   //Unknown algorithm identifier?
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

uint_t pkcs7GetKeyLength(const uint8_t *oid, size_t length)
{
   uint_t keyLen;

#if (PKCS7_DES_SUPPORT == ENABLED && DES_SUPPORT == ENABLED)
   //DES-CBC algorithm identifier?
   if(OID_COMP(oid, length, DES_CBC_OID) == 0)
   {
      keyLen = 8;
   }
   else
#endif
#if (PKCS7_3DES_SUPPORT == ENABLED && DES3_SUPPORT == ENABLED)
   //DES-EDE3-CBC algorithm identifier?
   if(OID_COMP(oid, length, DES_EDE3_CBC_OID) == 0)
   {
      keyLen = 24;
   }
   else
#endif
#if (PKCS7_AES_SUPPORT == ENABLED && AES_SUPPORT == ENABLED)
   //AES128-CBC algorithm identifier?
   if(OID_COMP(oid, length, AES128_CBC_OID) == 0)
   {
      keyLen = 16;
   }
   //AES192-CBC algorithm identifier?
   else if(OID_COMP(oid, length, AES192_CBC_OID) == 0)
   {
      keyLen = 24;
   }
   //AES256-CBC algorithm identifier?
   else if(OID_COMP(oid, length, AES256_CBC_OID) == 0)
   {
      keyLen = 32;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      keyLen = 0;
   }

   //Return the encryption key length that matches the specified OID
   return keyLen;
}


/**
 * @brief Compare attributes
 * @param[in] attribute1 Pointer to the first attribute
 * @param[in] attributeLen1 Length of the first attribute
 * @param[in] attribute2 Pointer to the second attribute
 * @param[in] attributeLen2 Length of the second attribute
 * @retval 0 Attributes are equal
 * @retval -1 The first attribute precedes the second attribute
 * @retval 1 The second attribute precedes the first attribute
 **/

int_t pkcs7CompAttributes(const uint8_t *attribute1, size_t attributeLen1,
   const uint8_t *attribute2, size_t attributeLen2)
{
   size_t i;
   size_t n;

   //The encodings are compared as octet strings with the shorter components
   //being padded at their trailing end with 0-octets
   n = MIN(attributeLen1, attributeLen2);

   //Compare octet strings
   for(i = 0; i < n; i++)
   {
      if(attribute1[i] < attribute2[i])
      {
         return -1;
      }
      else if(attribute1[i] > attribute2[i])
      {
         return 1;
      }
      else
      {
      }
   }

   //Check whether the first attribute is shorter than the second attribute
   if(attributeLen1 < attributeLen2)
   {
      return -1;
   }
   else if(attributeLen1 > attributeLen2)
   {
      return 1;
   }
   else
   {
   }

   //The attributes are equal
   return 0;
}


/**
 * @brief Digest the DER encoding of the authenticatedAttributes field
 * @param[in] signerInfo Pointer to the signer information
 * @param[in] data Content octets of authenticatedAttributes field
 * @param[in] length Length of the content octets
 * @param[out] digest Resulting message digest
 * @return Error code
 **/

error_t pkcs7DigestAuthenticatedAttributes(const Pkcs7SignerInfo *signerInfo,
   const uint8_t *data, size_t length, uint8_t *digest)
{
   error_t error;
   size_t n;
   uint8_t buffer[8];
   const HashAlgo *hashAlgo;
   HashContext hashContext;
   Asn1Tag tag;

   //The rsaEncryption algorithm identifier is used to identify RSA (PKCS #1
   //v1.5) signature values regardless of the message digest algorithm
   //employed (refer to RFC 3370, section 3.2)
   if(OID_COMP(signerInfo->digestEncryptionAlgo.oid.value,
      signerInfo->digestEncryptionAlgo.oid.length, RSA_ENCRYPTION_OID) == 0)
   {
      //CMS implementations that include the RSA (PKCS #1 v1.5) signature
      //algorithm must support the rsaEncryption signature value algorithm
      //identifier
      hashAlgo = pkcs7GetHashAlgo(signerInfo->digestAlgo.oid.value,
         signerInfo->digestAlgo.oid.length);
   }
   else
   {
      //CMS implementations may support RSA (PKCS #1 v1.5) signature value
      //algorithm identifiers that specify both the RSA (PKCS #1 v1.5)
      //signature algorithm and the message digest algorithm
      hashAlgo = pkcs7GetSignHashAlgo(signerInfo->digestEncryptionAlgo.oid.value,
         signerInfo->digestEncryptionAlgo.oid.length);
   }

   //Valid hash algorithm?
   if(hashAlgo != NULL)
   {
      //The IMPLICIT [0] tag in the authenticatedAttributes field is not part
      //of the Attributes value. The Attributes value's tag is SET OF (refer to
      //RFC 2315, section 9.3)
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SET;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1WriteHeader(&tag, FALSE, buffer, &n);

      //Chech status code
      if(!error)
      {
         //The DER encoding of the SET OF tag, rather than of the IMPLICIT [0]
         //tag, is to be digested along with the length and contents octets of
         //the Attributes value
         hashAlgo->init(&hashContext);
         hashAlgo->update(&hashContext, buffer, n);
         hashAlgo->update(&hashContext, data, length);
         hashAlgo->final(&hashContext, digest);

         //Debug message
         TRACE_DEBUG("Message digest:\r\n");
         TRACE_DEBUG_ARRAY("  ", digest, hashAlgo->digestSize);
      }
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_HASH_ALGO;
   }

   //Return status code
   return error;
}

#endif
