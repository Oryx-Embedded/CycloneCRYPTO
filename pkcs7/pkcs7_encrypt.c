/**
 * @file pkcs7_encrypt.c
 * @brief PKCS #7 message encryption
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
#include "pkcs7/pkcs7_format.h"
#include "pkcs7/pkcs7_encrypt.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cbc.h"
#include "pkix/x509_key_parse.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS7_SUPPORT == ENABLED)


/**
 * @brief Encrypt enveloped-data content
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[in] contentEncrAlgo Content encryption algorithm
 * @param[in] plaintext Pointer to the message to be encrypted
 * @param[in] plaintextLen Length of the message, in bytes
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7EncryptEnvelopedData(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertInfo *recipientCertInfo,
   const Pkcs7ContentEncrAlgo *contentEncrAlgo, const uint8_t *plaintext,
   size_t plaintextLen, uint8_t *output, size_t *written)
{
   error_t error;
   Pkcs7EnvelopedData envelopedData;
   const CipherAlgo *cipherAlgo;
   uint8_t iv[16];

   //Retrieve cipher algorithm
   cipherAlgo = pkcs7GetCipherAlgo(contentEncrAlgo->oid.value,
      contentEncrAlgo->oid.length);
   //Invalid cipher algorithm?
   if(cipherAlgo == NULL)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //Generate a random initialization vector
   error = prngAlgo->generate(prngContext, iv, cipherAlgo->blockSize);
   //Any error to report?
   if(error)
      return error;

   //Clear EnvelopedData structure
   osMemset(&envelopedData, 0, sizeof(Pkcs7EnvelopedData));

   //version is the syntax version number
   envelopedData.version = PKCS7_VERSION_0;

   //recipientInfos is a collection of per-recipient information
   envelopedData.recipientInfos.numRecipientInfos = 1,
   envelopedData.recipientInfos.recipientInfos[0].version = PKCS7_VERSION_0;
   envelopedData.recipientInfos.recipientInfos[0].issuerAndSerialNumber.name.raw = recipientCertInfo->tbsCert.issuer.raw;
   envelopedData.recipientInfos.recipientInfos[0].issuerAndSerialNumber.serialNumber = recipientCertInfo->tbsCert.serialNumber;
   envelopedData.recipientInfos.recipientInfos[0].keyEncryptionAlgo.oid.value = RSA_ENCRYPTION_OID;
   envelopedData.recipientInfos.recipientInfos[0].keyEncryptionAlgo.oid.length = sizeof(RSA_ENCRYPTION_OID);

   //encryptedContentInfo is the encrypted content information
   envelopedData.encryptedContentInfo.contentType.value = PKCS7_DATA_OID;
   envelopedData.encryptedContentInfo.contentType.length = sizeof(PKCS7_DATA_OID);
   envelopedData.encryptedContentInfo.contentEncrAlgo.oid.value = contentEncrAlgo->oid.value;
   envelopedData.encryptedContentInfo.contentEncrAlgo.oid.length = contentEncrAlgo->oid.length;
   envelopedData.encryptedContentInfo.contentEncrAlgo.iv.value = iv;
   envelopedData.encryptedContentInfo.contentEncrAlgo.iv.length = cipherAlgo->blockSize;

   //Format enveloped-data content
   error = pkcs7FormatEnvelopedData(prngAlgo, prngContext, recipientCertInfo,
      &envelopedData, plaintext, plaintextLen, output, written);

   //Return status code
   return error;
}


/**
 * @brief Perform key encryption
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[in] plaintext Pointer to the key to be encrypted
 * @param[in] plaintextLen Length of the key, in bytes
 * @param[out] ciphertext Ciphertext resulting from the encryption operation
 * @param[out] ciphertextLen Length of the resulting ciphertext
 * @return Error code
 **/

error_t pkcs7EncryptKey(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertInfo *recipientCertInfo, const uint8_t *plaintext,
   size_t plaintextLen, uint8_t *ciphertext, size_t *ciphertextLen)
{
#if (PKCS7_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   RsaPublicKey rsaPublicKey;

   //Initialize RSA public key
   rsaInitPublicKey(&rsaPublicKey);

   //Import the RSA public key
   error = x509ImportRsaPublicKey(&rsaPublicKey,
      &recipientCertInfo->tbsCert.subjectPublicKeyInfo);

   //Check status code
   if(!error)
   {
      //If the output parameter is NULL, then the function calculates the
      //length of the ciphertext without copying any data
      if(ciphertext != NULL)
      {
         //Perform RSA encryption
         error = rsaesPkcs1v15Encrypt(prngAlgo, prngContext, &rsaPublicKey,
            plaintext, plaintextLen, ciphertext, ciphertextLen);
      }
      else
      {
         //Length of the resulting ciphertext
         *ciphertextLen = mpiGetByteLength(&rsaPublicKey.n);
      }
   }

   //Release previously allocated resources
   rsaFreePublicKey(&rsaPublicKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Perform data encryption
 * @param[in] encryptedContentInfo Pointer to the encryptedContentInfo structure
 * @param[in] key Pointer to the encryption key
 * @param[in] keyLen Length of the encryption key, in bytes
 * @param[in] plaintext Pointer to the plaintext data to be encrypted
 * @param[in] plaintextLen Length of the plaintext, in bytes
 * @param[out] ciphertext Ciphertext resulting from the encryption operation
 * @param[out] ciphertextLen Length of the resulting ciphertext
 * @return Error code
 **/

error_t pkcs7EncryptData(const Pkcs7EncryptedContentInfo *encryptedContentInfo,
   const uint8_t *key, size_t keyLen, const uint8_t *plaintext,
   size_t plaintextLen, uint8_t *ciphertext, size_t *ciphertextLen)
{
   error_t error;
   size_t i;
   size_t n;
   size_t ivLen;
   size_t paddingLen;
   uint8_t iv[MAX_CIPHER_BLOCK_SIZE];
   const CipherAlgo *cipherAlgo;
   CipherContext cipherContext;

   //Retrieve cipher algorithm
   cipherAlgo = pkcs7GetCipherAlgo(encryptedContentInfo->contentEncrAlgo.oid.value,
      encryptedContentInfo->contentEncrAlgo.oid.length);
   //Invalid cipher algorithm?
   if(cipherAlgo == NULL)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //Obtain the key length in octets
   n = pkcs7GetKeyLength(encryptedContentInfo->contentEncrAlgo.oid.value,
      encryptedContentInfo->contentEncrAlgo.oid.length);
   //Invalid key length?
   if(n == 0)
      return ERROR_UNSUPPORTED_CIPHER_ALGO;

   //Check the length of the encryption key
   if(keyLen != n)
      return ERROR_DECRYPTION_FAILED;

   //Retrieve the length of the initialization vector
   ivLen = encryptedContentInfo->contentEncrAlgo.iv.length;

   //Check the length of the initialization vector
   if(ivLen != cipherAlgo->blockSize)
      return ERROR_DECRYPTION_FAILED;

   //Copy the initialization vector
   osMemcpy(iv, encryptedContentInfo->contentEncrAlgo.iv.value, ivLen);

   //Load encryption key
   error = cipherAlgo->init(&cipherContext, key, keyLen);
   //Any error to report?
   if(error)
      return error;

   //Get the actual amount of bytes in the last block
   paddingLen = plaintextLen % cipherAlgo->blockSize;

   //Determine the length of the padding string
   if(paddingLen > 0)
   {
      paddingLen = cipherAlgo->blockSize - paddingLen;
   }

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting ciphertext without performing encryption
   if(ciphertext != NULL)
   {
      //Copy the data to encrypt
      osMemmove(ciphertext, plaintext, plaintextLen);

      //The content must be padded to a multiple of the block size
      for(i = 0; i <= paddingLen; i++)
      {
         ciphertext[plaintextLen + i] = (uint8_t) paddingLen;
      }

      //Perform CBC encryption
      error = cbcEncrypt(cipherAlgo, &cipherContext, iv, ciphertext, ciphertext,
         plaintextLen + paddingLen);
      //Any error to report?
      if(error)
         return error;
   }

   //Return the length of the ciphertext
   *ciphertextLen = plaintextLen + paddingLen;

   //Successful processing
   return NO_ERROR;
}

#endif
