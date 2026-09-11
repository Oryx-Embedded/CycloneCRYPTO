/**
 * @file pkcs7_decrypt.c
 * @brief PKCS #7 message decryption
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkcs7/pkcs7_parse.h"
#include "pkcs7/pkcs7_decrypt.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cbc.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS7_SUPPORT == ENABLED)


/**
 * @brief Decrypt enveloped-data content
 * @param[in] envelopedData Pointer to the enveloped-data content
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[in] recipientPrivateKey Recipient's private key
 * @param[out] plaintext Plaintext resulting from the decryption operation
 * @param[out] plaintextLen Length of the resulting plaintext
 * @return Error code
 **/

error_t pkcs7DecryptEnvelopedData(const Pkcs7EnvelopedData *envelopedData,
   const X509CertInfo *recipientCertInfo, const void *recipientPrivateKey,
   uint8_t *plaintext, size_t *plaintextLen)
{
   error_t error;
   size_t keyLen;
   uint8_t key[PKCS7_MAX_ENCR_KEY_SIZE];
   Pkcs7RecipientInfo recipientInfo;

   //recipientInfos is a collection of per-recipient information. There must be
   //at least one element in the collection (refer to RFC 2315, section 10.1)
   error = pkcs7FindRecipient(&envelopedData->recipientInfos, recipientCertInfo,
      &recipientInfo);

   //Any matching recipientInfo entry?
   if(!error)
   {
      //Perform key decryption
      error = pkcs7DecryptKey(&recipientInfo, recipientPrivateKey, key, &keyLen);

      //Check status code
      if(!error)
      {
         //Perform data decryption
         error = pkcs7DecryptData(&envelopedData->encryptedContentInfo, key,
            keyLen, plaintext, plaintextLen);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Perform key decryption
 * @param[in] recipientInfo Pointer to the RecipientInfo structure
 * @param[in] recipientPrivateKey Recipient's private key
 * @param[out] plaintext Key resulting from the decryption operation
 * @param[out] plaintextLen Length of the resulting key
 * @return Error code
 **/

error_t pkcs7DecryptKey(const Pkcs7RecipientInfo *recipientInfo,
   const void *recipientPrivateKey, uint8_t *plaintext, size_t *plaintextLen)
{
   error_t error;

#if (PKCS7_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA encryption algorithm?
   if(OID_COMP(recipientInfo->keyEncryptionAlgo.oid.value,
      recipientInfo->keyEncryptionAlgo.oid.length, RSA_ENCRYPTION_OID) == 0)
   {
      //Perform RSA decryption
      error = rsaesPkcs1v15Decrypt(recipientPrivateKey,
         recipientInfo->encryptedKey.value, recipientInfo->encryptedKey.length,
         plaintext, PKCS7_MAX_ENCR_KEY_SIZE, plaintextLen);
   }
   else
#endif
   //Unknown algorithm?
   {
      //Report an error
      error = ERROR_DECRYPTION_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Perform data decryption
 * @param[in] encryptedContentInfo Pointer to the encryptedContentInfo structure
 * @param[in] key Pointer to the encryption key
 * @param[in] keyLen Length of the encryption key, in bytes
 * @param[out] plaintext Plaintext resulting from the decryption operation
 * @param[out] plaintextLen Length of the resulting plaintext
 * @return Error code
 **/

error_t pkcs7DecryptData(const Pkcs7EncryptedContentInfo *encryptedContentInfo,
   const uint8_t *key, size_t keyLen, uint8_t *plaintext, size_t *plaintextLen)
{
   error_t error;
   uint32_t bad;
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

   //Get the length of the ciphertext
   n = encryptedContentInfo->encryptedContent.length;

   //Perform CBC decryption
   error = cbcDecrypt(cipherAlgo, &cipherContext, iv,
      encryptedContentInfo->encryptedContent.value, plaintext, n);
   //Any error to report?
   if(error)
      return error;

   //Verify padding string
   bad = pkcs7VerifyPadding(plaintext, n, cipherAlgo->blockSize, &paddingLen);

   //Strip padding bytes from the plaintext
   *plaintextLen = n - paddingLen;

   //Return status code
   return bad ? ERROR_DECRYPTION_FAILED : NO_ERROR;
}


/**
 * @brief CBC padding verification (constant time)
 * @param[in] data Pointer to the plaintext data
 * @param[in] dataLen Length of the plaintext data
 * @param[in] blockSize Block size of the underlying cipher algorithm
 * @param[out] paddingLen Length of the padding string
 * @return The function returns 0 if the padding is correct, 1 on failure
 **/

uint32_t pkcs7VerifyPadding(const uint8_t *data, size_t dataLen,
   size_t blockSize, size_t *paddingLen)
{
   size_t i;
   size_t n;
   uint8_t b;
   uint8_t mask;
   uint32_t c;
   uint32_t bad;

   //Retrieve the length of the padding string
   n = data[dataLen - 1];

   //Ensure that length of the padding string is valid
   bad = CRYPTO_TEST_LT_32(n, 1);
   bad |= CRYPTO_TEST_GT_32(n, blockSize);
   bad |= CRYPTO_TEST_GT_32(n, dataLen);

   //Each byte in the padding data must be filled with the padding length value
   for(i = 1; i < dataLen && i < 256; i++)
   {
      //Read current byte
      b = data[dataLen - 1 - i];

      //Verify that the padding string is correct
      c = CRYPTO_TEST_LT_32(i, n);
      mask = CRYPTO_SELECT_8(b, n, c);
      bad |= CRYPTO_TEST_NEQ_8(b, mask);
   }

   //Save the length of the padding string
   *paddingLen = CRYPTO_SELECT_32(n, 0, bad);

   //Return status code
   return bad;
}


/**
 * @brief Search a list of per-recipient informations for a given recipient
 * @param[in] recipientInfos Pointer to the collection of per-recipient
 *   information
 * @param[in] recipientCertInfo Recipient's certificate
 * @param[out] recipientInfo Pointer to the matching RecipientInfo structure,
 *   if any
 * @return Error code
 **/

error_t pkcs7FindRecipient(const Pkcs7RecipientInfos *recipientInfos,
   const X509CertInfo *recipientCertInfo, Pkcs7RecipientInfo *recipientInfo)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *data;

   //Point to the first recipientInfo entry
   data = recipientInfos->raw.value;
   length = recipientInfos->raw.length;

   //recipientInfos is a collection of per-recipient information. There must be
   //at least one element in the collection (refer to RFC 2315, section 10.1)
   while(length > 0)
   {
      //Per-recipient information is represented in the type RecipientInfo
      error = pkcs7ParseRecipientInfo(data, length, &n, recipientInfo);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Matching issuer name?
      if(x509CompareName(recipientInfo->issuerAndSerialNumber.name.raw.value,
         recipientInfo->issuerAndSerialNumber.name.raw.length,
         recipientCertInfo->tbsCert.issuer.raw.value,
         recipientCertInfo->tbsCert.issuer.raw.length))
      {
         //Compare the length of the serial numbers
         if(recipientInfo->issuerAndSerialNumber.serialNumber.length ==
            recipientCertInfo->tbsCert.serialNumber.length)
         {
            //Matching serial number?
            if(osMemcmp(recipientInfo->issuerAndSerialNumber.serialNumber.value,
               recipientCertInfo->tbsCert.serialNumber.value,
               recipientCertInfo->tbsCert.serialNumber.length) == 0)
            {
               //A matching recipient has been found
               return NO_ERROR;
            }
         }
      }

      //Next field
      data += n;
      length -= n;
   }

   //The specified recipient was not found
   return ERROR_NOT_FOUND;
}

#endif
