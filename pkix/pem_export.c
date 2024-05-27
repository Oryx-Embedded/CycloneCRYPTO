/**
 * @file pem_export.c
 * @brief PEM file export functions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkix/pem_export.h"
#include "pkix/pkcs8_key_format.h"
#include "pkix/x509_cert_create.h"
#include "pkix/x509_key_format.h"
#include "encoding/asn1.h"
#include "mpi/mpi.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Export an X.509 certificate to PEM format
 * @param[in] cert Pointer to the DER-encoded certificate
 * @param[in] certLen Length of the DER-encoded certificate, in bytes
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportCertificate(const uint8_t *cert, size_t certLen,
   char_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(cert == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //X.509 certificates are encoded using the "CERTIFICATE" label
   error = pemEncodeFile(cert, certLen, "CERTIFICATE", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export a certificate revocation list to PEM format
 * @param[in] crl Pointer to the DER-encoded CRL
 * @param[in] crlLen Length of the DER-encoded CRL, in bytes
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportCrl(const uint8_t *crl, size_t crlLen,
   char_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(crl == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //CRLs are encoded using the "X509 CRL" label
   error = pemEncodeFile(crl, crlLen, "X509 CRL", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export a certification signing request to PEM format
 * @param[in] csr Pointer to the DER-encoded CSR
 * @param[in] csrLen Length of the DER-encoded CSR, in bytes
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportCsr(const uint8_t *csr, size_t csrLen,
   char_t *output, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(csr == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //CSRs are encoded using the "CERTIFICATE REQUEST" label
   error = pemEncodeFile(csr, csrLen, "CERTIFICATE REQUEST", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an RSA public key to PEM format
 * @param[in] publicKey RSA public key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportRsaPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
   //structure (refer to RFC 7468, section 13)
   publicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
   publicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

   //Format the SubjectPublicKeyInfo structure
   error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
      (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemEncodeFile(output, n, "PUBLIC KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an RSA private key to PEM format
 * @param[in] privateKey RSA private key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportRsaPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //Point to the buffer where to write the PrivateKeyInfo structure
   p = (uint8_t *) output;
   //Total length of the PrivateKeyInfo structure
   length = 0;

   //Format Version field (refer to RFC 5208, section 5)
   error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //The PrivateKeyAlgorithm identifies the private-key algorithm
   publicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
   publicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

   //Format PrivateKeyAlgorithm field
   error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //Format PrivateKey field
   error = pkcs8FormatRsaPrivateKey(privateKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //The PrivateKeyInfo structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = (uint8_t *) output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the PrivateKeyInfo structure
   n = tag.totalLength;

   //PKCS#8 private keys are encoded using the "PRIVATE KEY" label
   error = pemEncodeFile(output, n, "PRIVATE KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an RSA-PSS public key to PEM format
 * @param[in] publicKey RSA-PSS public key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportRsaPssPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
   //structure (refer to RFC 7468, section 13)
   publicKeyInfo.oid.value = RSASSA_PSS_OID;
   publicKeyInfo.oid.length = sizeof(RSASSA_PSS_OID);

   //Format the SubjectPublicKeyInfo structure
   error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
      (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemEncodeFile(output, n, "PUBLIC KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an RSA-PSS private key to PEM format
 * @param[in] privateKey RSA-PSS private key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportRsaPssPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //Point to the buffer where to write the PrivateKeyInfo structure
   p = (uint8_t *) output;
   //Total length of the PrivateKeyInfo structure
   length = 0;

   //Format Version field (refer to RFC 5208, section 5)
   error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //The PrivateKeyAlgorithm identifies the private-key algorithm
   publicKeyInfo.oid.value = RSASSA_PSS_OID;
   publicKeyInfo.oid.length = sizeof(RSASSA_PSS_OID);

   //Format PrivateKeyAlgorithm field
   error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //Format PrivateKey field
   error = pkcs8FormatRsaPrivateKey(privateKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //The PrivateKeyInfo structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = (uint8_t *) output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the PrivateKeyInfo structure
   n = tag.totalLength;

   //PKCS#8 private keys are encoded using the "PRIVATE KEY" label
   error = pemEncodeFile(output, n, "PRIVATE KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export a DSA public key to PEM format
 * @param[in] publicKey DSA public key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportDsaPublicKey(const DsaPublicKey *publicKey,
   char_t *output, size_t *written)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
   //structure (refer to RFC 7468, section 13)
   publicKeyInfo.oid.value = DSA_OID;
   publicKeyInfo.oid.length = sizeof(DSA_OID);

   //Format the SubjectPublicKeyInfo structure
   error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
      (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemEncodeFile(output, n, "PUBLIC KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export a DSA private key to PEM format
 * @param[in] privateKey DSA private key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportDsaPrivateKey(const DsaPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //Point to the buffer where to write the PrivateKeyInfo structure
   p = (uint8_t *) output;
   //Total length of the PrivateKeyInfo structure
   length = 0;

   //Format Version field (refer to RFC 5208, section 5)
   error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //The PrivateKeyAlgorithm identifies the private-key algorithm
   publicKeyInfo.oid.value = DSA_OID;
   publicKeyInfo.oid.length = sizeof(DSA_OID);

   //Format PrivateKeyAlgorithm field
   error = x509FormatAlgoId(&publicKeyInfo, &privateKey->params,
      p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //Format PrivateKey field
   error = pkcs8FormatDsaPrivateKey(privateKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //The PrivateKeyInfo structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = (uint8_t *) output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the PrivateKeyInfo structure
   n = tag.totalLength;

   //PKCS#8 private keys are encoded using the "PRIVATE KEY" label
   error = pemEncodeFile(output, n, "PRIVATE KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export EC domain parameters to PEM format
 * @param[in] curveInfo Elliptic curve parameters
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportEcParameters(const EcCurveInfo *curveInfo,
   char_t *output, size_t *written)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Check parameters
   if(curveInfo == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format ECParameters field
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
   tag.length = curveInfo->oidSize;
   tag.value = curveInfo->oid;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //EC domain parameters are encoded using the "EC PARAMETERS" label
   error = pemEncodeFile(output, n, "EC PARAMETERS", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EC public key to PEM format
 * @param[in] curveInfo Elliptic curve parameters
 * @param[in] publicKey EC public key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportEcPublicKey(const EcCurveInfo *curveInfo,
   const EcPublicKey *publicKey, char_t *output, size_t *written)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(curveInfo == NULL || publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
   //structure (refer to RFC 7468, section 13)
   publicKeyInfo.oid.value = EC_PUBLIC_KEY_OID;
   publicKeyInfo.oid.length = sizeof(EC_PUBLIC_KEY_OID);
   publicKeyInfo.ecParams.namedCurve.value = curveInfo->oid;
   publicKeyInfo.ecParams.namedCurve.length = curveInfo->oidSize;

   //Format the SubjectPublicKeyInfo structure
   error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
      (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemEncodeFile(output, n, "PUBLIC KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EC private key to PEM format
 * @param[in] curveInfo Elliptic curve parameters
 * @param[in] privateKey EC private key
 * @param[in] publicKey EC public key (optional parameter)
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportEcPrivateKey(const EcCurveInfo *curveInfo,
   const EcPrivateKey *privateKey, const EcPublicKey *publicKey,
   char_t *output, size_t *written)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(curveInfo == NULL || privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //Point to the buffer where to write the PrivateKeyInfo structure
   p = (uint8_t *) output;
   //Total length of the PrivateKeyInfo structure
   length = 0;

   //Format Version field (refer to RFC 5208, section 5)
   error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //The PrivateKeyAlgorithm identifies the private-key algorithm
   publicKeyInfo.oid.value = EC_PUBLIC_KEY_OID;
   publicKeyInfo.oid.length = sizeof(EC_PUBLIC_KEY_OID);
   publicKeyInfo.ecParams.namedCurve.value = curveInfo->oid;
   publicKeyInfo.ecParams.namedCurve.length = curveInfo->oidSize;

   //Format PrivateKeyAlgorithm field
   error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //Format PrivateKey field
   error = pkcs8FormatEcPrivateKey(curveInfo, privateKey, publicKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //The PrivateKeyInfo structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = (uint8_t *) output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the PrivateKeyInfo structure
   n = tag.totalLength;

   //PKCS#8 private keys are encoded using the "PRIVATE KEY" label
   error = pemEncodeFile(output, n, "PRIVATE KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EdDSA public key to PEM format
 * @param[in] curveInfo Elliptic curve parameters
 * @param[in] publicKey EdDSA public key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportEddsaPublicKey(const EcCurveInfo *curveInfo,
   const EddsaPublicKey *publicKey, char_t *output, size_t *written)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(curveInfo == NULL || publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
   //structure (refer to RFC 7468, section 13)
   publicKeyInfo.oid.value = curveInfo->oid;
   publicKeyInfo.oid.length = curveInfo->oidSize;

   //Format the SubjectPublicKeyInfo structure
   error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
      (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Public keys are encoded using the "PUBLIC KEY" label
   error = pemEncodeFile(output, n, "PUBLIC KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EdDSA private key to PEM format
 * @param[in] curveInfo Elliptic curve parameters
 * @param[in] privateKey EdDSA private key
 * @param[out] output Buffer where to store the PEM encoding
 * @param[out] written Length of the resulting PEM encoding
 * @return Error code
 **/

error_t pemExportEddsaPrivateKey(const EcCurveInfo *curveInfo,
   const EddsaPrivateKey *privateKey, char_t *output, size_t *written)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;
   X509SubjectPublicKeyInfo publicKeyInfo;

   //Check parameters
   if(curveInfo == NULL || privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the SubjectPublicKeyInfo structure
   osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //Point to the buffer where to write the PrivateKeyInfo structure
   p = (uint8_t *) output;
   //Total length of the PrivateKeyInfo structure
   length = 0;

   //Format Version field (refer to RFC 5208, section 5)
   error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //The PrivateKeyAlgorithm identifies the private-key algorithm
   publicKeyInfo.oid.value = curveInfo->oid;
   publicKeyInfo.oid.length = curveInfo->oidSize;

   //Format PrivateKeyAlgorithm field
   error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //Advance data pointer
   if(output != NULL)
      p += n;

   //Format PrivateKey field
   error = pkcs8FormatEddsaPrivateKey(curveInfo, privateKey, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the PrivateKeyInfo structure
   length += n;

   //The PrivateKeyInfo structure is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = (uint8_t *) output;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the PrivateKeyInfo structure
   n = tag.totalLength;

   //PKCS#8 private keys are encoded using the "PRIVATE KEY" label
   error = pemEncodeFile(output, n, "PRIVATE KEY", output, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
