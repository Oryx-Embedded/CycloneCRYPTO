/**
 * @file pkcs7_sign_verify.c
 * @brief PKCS #7 signature verification
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
#include "pkcs7/pkcs7_parse.h"
#include "pkcs7/pkcs7_sign_verify.h"
#include "hash/hash_algorithms.h"
#include "pkix/x509_key_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS7_SUPPORT == ENABLED)


/**
 * @brief Verify signature over signed-data content
 * @param[in] signedData Pointer to the signed-data content
 * @param[in] signerInfo Pointer to the signer information
 * @param[in] signerCertInfo Signer's certificate
 * @return Error code
 **/

error_t pkcs7VerifySignedData(const Pkcs7SignedData *signedData,
   const Pkcs7SignerInfo *signerInfo, const X509CertInfo *signerCertInfo)
{
   error_t error;
   Asn1Tag tag;
   uint8_t calcDigest[MAX_HASH_DIGEST_SIZE];
   const HashAlgo *hashAlgo;
   const X509OctetString *msgDigest;

   //Point to the PKCS #9 Message Digest attribute
   msgDigest = &signerInfo->authenticatedAttributes.messageDigest;

   //Debug message
   TRACE_DEBUG("Message digest:\r\n");
   TRACE_DEBUG_ARRAY("  ", msgDigest->value, msgDigest->length);

   //Get the hash algorithm that matches the specified OID
   hashAlgo = pkcs7GetHashAlgo(signerInfo->digestAlgo.oid.value,
      signerInfo->digestAlgo.oid.length);

   //Valid hash algorithm?
   if(hashAlgo != NULL)
   {
      //The initial input to the message-digesting process is the "value" of
      //the content being signed (refer to RFC 2315, section 9.3)
      error = asn1ReadOctetString(signedData->contentInfo.content.value,
         signedData->contentInfo.content.length, &tag);

      //Check status code
      if(!error)
      {
         //Only the contents octets of the DER encoding of that field are
         //digested, not the identifier octets or the length octets
         error = hashAlgo->compute(tag.value, tag.length, calcDigest);
      }

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_DEBUG("Calculated digest:\r\n");
         TRACE_DEBUG_ARRAY("  ", calcDigest, hashAlgo->digestSize);

         //Check the message digest of the content
         if(msgDigest->length == hashAlgo->digestSize ||
            osMemcmp(msgDigest->value, calcDigest, hashAlgo->digestSize) == 0)
         {
            //Digest the DER encoding of the authenticatedAttributes field
            error = pkcs7DigestAuthenticatedAttributes(signerInfo,
               signerInfo->authenticatedAttributes.raw.value,
               signerInfo->authenticatedAttributes.raw.length, calcDigest);
         }
         else
         {
            //The message digest is not valid
            error = ERROR_INVALID_SIGNATURE;
         }
      }

      //Check status code
      if(!error)
      {
         //The input to the signature verification process includes the result
         //of the message digest calculation process and the signer's public key
         error = pkcs7VerifySignature(calcDigest, signerInfo,
            &signerCertInfo->tbsCert.subjectPublicKeyInfo,
            &signerInfo->encryptedDigest);
      }
   }
   else
   {
      //The specified hash algorithm is not supported
      error = ERROR_UNSUPPORTED_HASH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Signature verification
 * @param[in] digest Message digest
 * @param[in] signerInfo Pointer to the signer information
 * @param[in] publicKeyInfo Signer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t pkcs7VerifySignature(const uint8_t *digest,
   const Pkcs7SignerInfo *signerInfo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
   error_t error;
   size_t oidLen;
   const uint8_t *oid;

   //Get the signature algorithm identifier
   oid = signerInfo->digestEncryptionAlgo.oid.value;
   oidLen = signerInfo->digestEncryptionAlgo.oid.length;

#if (PKCS7_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, MD5_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA1_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA224_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA256_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA384_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA512_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
      error = pkcs7VerifyRsaSignature(digest, signerInfo, publicKeyInfo,
         signature);
   }
   else
#endif
   //Unknown signature algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature verification
 * @param[in] digest Message digest
 * @param[in] signerInfo Pointer to the signer information
 * @param[in] publicKeyInfo Signer's public key
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t pkcs7VerifyRsaSignature(const uint8_t *digest,
   const Pkcs7SignerInfo *signerInfo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509OctetString *signature)
{
#if (PKCS7_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   const HashAlgo *hashAlgo;
   RsaPublicKey rsaPublicKey;

   //Initialize RSA public key
   rsaInitPublicKey(&rsaPublicKey);

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
      //Import the RSA public key
      error = x509ImportRsaPublicKey(&rsaPublicKey, publicKeyInfo);

      //Check status code
      if(!error)
      {
         //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
         error = rsassaPkcs1v15Verify(&rsaPublicKey, hashAlgo, digest,
            signature->value, signature->length);
      }
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
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
 * @brief Search a list of per-signer informations for a given signer
 * @param[in] signerInfos Pointer to the collection of per-signer
 *   information
 * @param[in] signerCertInfo Signer's certificate
 * @param[out] signerInfo Pointer to the matching SignerInfo structure,
 *   if any
 * @return Error code
 **/

error_t pkcs7FindSigner(const Pkcs7SignerInfos *signerInfos,
   const X509CertInfo *signerCertInfo, Pkcs7SignerInfo *signerInfo)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *data;

   //Point to the first signerInfo entry
   data = signerInfos->raw.value;
   length = signerInfos->raw.length;

   //signerInfos is a collection of per-signer information. There may be any
   //number of elements in the collection, including zero (refer to RFC 2315,
   //section 9.1)
   while(length > 0)
   {
      //Per-signer information is represented in the type SignerInfo
      error = pkcs7ParseSignerInfo(data, length, &n, signerInfo);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Matching issuer name?
      if(x509CompareName(signerInfo->issuerAndSerialNumber.name.raw.value,
         signerInfo->issuerAndSerialNumber.name.raw.length,
         signerCertInfo->tbsCert.issuer.raw.value,
         signerCertInfo->tbsCert.issuer.raw.length))
      {
         //Compare the length of the serial numbers
         if(signerInfo->issuerAndSerialNumber.serialNumber.length ==
            signerCertInfo->tbsCert.serialNumber.length)
         {
            //Matching serial number?
            if(osMemcmp(signerInfo->issuerAndSerialNumber.serialNumber.value,
               signerCertInfo->tbsCert.serialNumber.value,
               signerCertInfo->tbsCert.serialNumber.length) == 0)
            {
               //A matching signer has been found
               return NO_ERROR;
            }
         }
      }

      //Next field
      data += n;
      length -= n;
   }

   //The specified signer was not found
   return ERROR_NOT_FOUND;
}

#endif
