/**
 * @file pkcs7_sign_generate.c
 * @brief PKCS #7 signature generation
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
#include "pkcs7/pkcs7_sign_generate.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PKCS7_SUPPORT == ENABLED)


/**
 * @brief Generate signed-data content
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] content Pointer to the message to be signed
 * @param[in] contentLen Length of the message, in bytes
 * @param[in] signerCertInfo Signer's certificate
 * @param[in] authenticatedAttributes Collection of attributes that are signed
 * @param[in] unauthenticatedAttributes Collection of attributes that are not signed
 * @param[in] signatureAlgo Signature algorithm
 * @param[in] signerPrivateKey Pointer to the signer's private key
 * @param[out] output Buffer where to format the ASN.1 structure
 * @param[out] written Length of the resulting ASN.1 structure
 * @return Error code
 **/

error_t pkcs7GenerateSignedData(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *content, size_t contentLen, const X509CertInfo *signerCertInfo,
   const Pkcs7AuthenticatedAttributes *authenticatedAttributes,
   const Pkcs7UnauthenticatedAttributes *unauthenticatedAttributes,
   const X509SignAlgoId *signatureAlgo, const void *signerPrivateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   const HashAlgo *hashAlgo;
   Pkcs7SignedData signedData;
   uint8_t messageDigest[MAX_HASH_DIGEST_SIZE];

   //Get the signature hash algorithm
   hashAlgo = pkcs7GetSignHashAlgo(signatureAlgo->oid.value,
      signatureAlgo->oid.length);
   //Invalid algorithm?
   if(hashAlgo == NULL)
      return ERROR_INVALID_SIGNATURE_ALGO;

   //Only the contents octets of the DER encoding of that field are digested,
   //not the identifier octets or the length octets (refer to RFC 2315,
   //section 9.3)
   error = hashAlgo->compute(content, contentLen, messageDigest);
   //Any error to report?
   if(error)
      return error;

   //Clear SignedData structure
   osMemset(&signedData, 0, sizeof(Pkcs7SignedData));

   //version is the syntax version number
   signedData.version = PKCS7_VERSION_1;

   //digestAlgorithms is a collection of message-digest algorithm identifiers
   signedData.digestAlgos.numIdentifiers = 1;
   signedData.digestAlgos.identifiers[0].oid.value = hashAlgo->oid;
   signedData.digestAlgos.identifiers[0].oid.length = hashAlgo->oidSize;

   //contentInfo is the content that is signed. It can have any of the defined
   //content types
   signedData.contentInfo.contentType.value = PKCS7_DATA_OID;
   signedData.contentInfo.contentType.length = sizeof(PKCS7_DATA_OID);
   signedData.contentInfo.content.value = content;
   signedData.contentInfo.content.length = contentLen;

   //certificates is a set of PKCS #6 extended certificates and X.509
   //certificates
   signedData.certificates.numCertificates = 1;
   signedData.certificates.certificates[0].value = signerCertInfo->raw.value;
   signedData.certificates.certificates[0].length = signerCertInfo->raw.length;

   //crls is a set of certificate-revocation lists
   signedData.crls.numCrls = 0;

   //signerInfos is a collection of per-signer information
   signedData.signerInfos.numSignerInfos = 1;
   signedData.signerInfos.signerInfos[0].version = PKCS7_VERSION_1;
   signedData.signerInfos.signerInfos[0].issuerAndSerialNumber.name.raw = signerCertInfo->tbsCert.issuer.raw;
   signedData.signerInfos.signerInfos[0].issuerAndSerialNumber.serialNumber = signerCertInfo->tbsCert.serialNumber;
   signedData.signerInfos.signerInfos[0].digestAlgo.oid.value = hashAlgo->oid;
   signedData.signerInfos.signerInfos[0].digestAlgo.oid.length = hashAlgo->oidSize;

   //The authenticatedAttributes field is optional
   if(authenticatedAttributes != NULL)
   {
      //authenticatedAttributes is a set of attributes that are signed by the
      //signer
      signedData.signerInfos.signerInfos[0].authenticatedAttributes = *authenticatedAttributes;
      signedData.signerInfos.signerInfos[0].authenticatedAttributes.messageDigest.value = messageDigest;
      signedData.signerInfos.signerInfos[0].authenticatedAttributes.messageDigest.length = hashAlgo->digestSize;
   }

   //The unauthenticatedAttributes field is optional
   if(unauthenticatedAttributes != NULL)
   {
      //unauthenticatedAttributes is a set of attributes that are not signed by
      //the signer
      signedData.signerInfos.signerInfos[0].unauthenticatedAttributes = *unauthenticatedAttributes;
   }

   //digestEncryptionAlgorithm identifies the digest-encryption algorithm under
   //which the message digest and associated information are encrypted with the
   //signer's private key (refer to RFC 2315, section 9.2)
   signedData.signerInfos.signerInfos[0].digestEncryptionAlgo = *signatureAlgo;

   //Format signed-data content
   error = pkcs7FormatSignedData(prngAlgo, prngContext, &signedData,
      signerPrivateKey, output, written);

   //Return status code
   return error;
}


/**
 * @brief Signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] digest Message digest
 * @param[in] signerInfo Pointer to the signer information
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t pkcs7GenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *digest, const Pkcs7SignerInfo *signerInfo,
   const void *privateKey, uint8_t *output, size_t *written)
{
   error_t error;
   size_t oidLen;
   const uint8_t *oid;

   //Get the signature algorithm identifier
   oid = signerInfo->digestEncryptionAlgo.oid.value;
   oidLen = signerInfo->digestEncryptionAlgo.oid.length;

#if (PKCS7_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(OID_COMP(oid, oidLen, MD5_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA1_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA224_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA256_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA384_WITH_RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, SHA512_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
      error = pkcs7GenerateRsaSignature(digest, signerInfo, privateKey,
         output, written);
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
 * @brief RSA signature generation
 * @param[in] digest Message digest
 * @param[in] signerInfo Pointer to the signer information
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t pkcs7GenerateRsaSignature(const uint8_t *digest,
   const Pkcs7SignerInfo *signerInfo, const RsaPrivateKey *privateKey,
   uint8_t *output, size_t *written)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   const HashAlgo *hashAlgo;

   //Initialize status code
   error = NO_ERROR;

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting signature but will not generate a signature
   if(output != NULL)
   {
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
         //Generate RSA signature
         error = rsassaPkcs1v15Sign(privateKey, hashAlgo, digest, output,
            written);
      }
      else
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
   {
      //Length of the resulting RSA signature
      *written = mpiGetByteLength(&privateKey->n);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
