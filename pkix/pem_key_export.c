/**
 * @file pem_key_export.c
 * @brief PEM key file export functions
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
#include "pkix/pem_key_export.h"
#include "pkix/pkcs8_key_format.h"
#include "pkix/x509_key_format.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Export an RSA public key to PEM format
 * @param[in] publicKey RSA public key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (PKCS #1 or RFC 7468 format)
 * @return Error code
 **/

error_t pemExportRsaPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check output format
   if(format == PEM_PUBLIC_KEY_FORMAT_PKCS1)
   {
      //Format RSAPublicKey structure
      error = x509ExportRsaPublicKey(publicKey, (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //PKCS #1 public keys are encoded using the "RSA PUBLIC KEY" label
         error = pemEncodeFile(output, length, "RSA PUBLIC KEY", output,
            written);
      }
   }
   else if(format == PEM_PUBLIC_KEY_FORMAT_RFC7468 ||
      format == PEM_PUBLIC_KEY_FORMAT_DEFAULT)
   {
      X509SubjectPublicKeyInfo publicKeyInfo;

      //Clear the SubjectPublicKeyInfo structure
      osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

      //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
      //structure (refer to RFC 7468, section 13)
      publicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
      publicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

      //Format the SubjectPublicKeyInfo structure
      error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
         (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //Public keys are encoded using the "PUBLIC KEY" label (see RFC 7468,
         //section 13)
         error = pemEncodeFile(output, length, "PUBLIC KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an RSA private key to PEM format
 * @param[in] privateKey RSA private key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (PKCS #1 or PKCS #8 format)
 * @return Error code
 **/

error_t pemExportRsaPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check output format
   if(format == PEM_PRIVATE_KEY_FORMAT_PKCS1)
   {
      //Format RSAPrivateKey structure
      error = x509ExportRsaPrivateKey(privateKey, (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //PKCS #1 private keys are encoded using the "RSA PRIVATE KEY" label
         error = pemEncodeFile(output, length, "RSA PRIVATE KEY", output,
            written);
      }
   }
   else if(format == PEM_PRIVATE_KEY_FORMAT_PKCS8 ||
      format == PEM_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      size_t n;
      uint8_t *p;
      Asn1Tag tag;

      //Point to the buffer where to write the PrivateKeyInfo structure
      p = (uint8_t *) output;
      //Total length of the PrivateKeyInfo structure
      length = 0;

      //Format Version field (refer to RFC 5208, section 5)
      error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);

      //Check status code
      if(!error)
      {
         X509SubjectPublicKeyInfo publicKeyInfo;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Clear the SubjectPublicKeyInfo structure
         osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

         //The PrivateKeyAlgorithm identifies the private-key algorithm
         publicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
         publicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

         //Format PrivateKeyAlgorithm field
         error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Format PrivateKey field
         error = pkcs8FormatRsaPrivateKey(privateKey, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Update the length of the PrivateKeyInfo structure
         length += n;

         //The PrivateKeyInfo structure is encapsulated within a sequence
         tag.constructed = TRUE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_SEQUENCE;
         tag.length = length;

         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, (uint8_t *) output, &n);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the PrivateKeyInfo structure
         length = tag.totalLength;

         //Unencrypted PKCS #8 private keys are encoded using the "PRIVATE KEY"
         //label (refer to RFC 7468, section 10)
         error = pemEncodeFile(output, length, "PRIVATE KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an RSA-PSS public key to PEM format
 * @param[in] publicKey RSA-PSS public key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (RFC 7468 format only)
 * @return Error code
 **/

error_t pemExportRsaPssPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check output format
   if(format == PEM_PUBLIC_KEY_FORMAT_RFC7468 ||
      format == PEM_PUBLIC_KEY_FORMAT_DEFAULT)
   {
      X509SubjectPublicKeyInfo publicKeyInfo;

      //Clear the SubjectPublicKeyInfo structure
      osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

      //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
      //structure (refer to RFC 7468, section 13)
      publicKeyInfo.oid.value = RSASSA_PSS_OID;
      publicKeyInfo.oid.length = sizeof(RSASSA_PSS_OID);

      //Format the SubjectPublicKeyInfo structure
      error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
         (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //Public keys are encoded using the "PUBLIC KEY" label (see RFC 7468,
         //section 13)
         error = pemEncodeFile(output, length, "PUBLIC KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an RSA-PSS private key to PEM format
 * @param[in] privateKey RSA-PSS private key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (PKCS #8 format only)
 * @return Error code
 **/

error_t pemExportRsaPssPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format)
{
#if (RSA_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check output format
   if(format == PEM_PRIVATE_KEY_FORMAT_PKCS8 ||
      format == PEM_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      size_t n;
      uint8_t *p;
      Asn1Tag tag;

      //Point to the buffer where to write the PrivateKeyInfo structure
      p = (uint8_t *) output;
      //Total length of the PrivateKeyInfo structure
      length = 0;

      //Format Version field (refer to RFC 5208, section 5)
      error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);

      //Check status code
      if(!error)
      {
         X509SubjectPublicKeyInfo publicKeyInfo;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Clear the SubjectPublicKeyInfo structure
         osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

         //The PrivateKeyAlgorithm identifies the private-key algorithm
         publicKeyInfo.oid.value = RSASSA_PSS_OID;
         publicKeyInfo.oid.length = sizeof(RSASSA_PSS_OID);

         //Format PrivateKeyAlgorithm field
         error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Format PrivateKey field
         error = pkcs8FormatRsaPrivateKey(privateKey, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Update the length of the PrivateKeyInfo structure
         length += n;

         //The PrivateKeyInfo structure is encapsulated within a sequence
         tag.constructed = TRUE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_SEQUENCE;
         tag.length = length;

         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, (uint8_t *) output, &n);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the PrivateKeyInfo structure
         length = tag.totalLength;

         //Unencrypted PKCS #8 private keys are encoded using the "PRIVATE KEY"
         //label (refer to RFC 7468, section 10)
         error = pemEncodeFile(output, length, "PRIVATE KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export a DSA public key to PEM format
 * @param[in] publicKey DSA public key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (RFC 7468 format only)
 * @return Error code
 **/

error_t pemExportDsaPublicKey(const DsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check output format
   if(format == PEM_PUBLIC_KEY_FORMAT_RFC7468 ||
      format == PEM_PUBLIC_KEY_FORMAT_DEFAULT)
   {
      X509SubjectPublicKeyInfo publicKeyInfo;

      //Clear the SubjectPublicKeyInfo structure
      osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

      //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
      //structure (refer to RFC 7468, section 13)
      publicKeyInfo.oid.value = DSA_OID;
      publicKeyInfo.oid.length = sizeof(DSA_OID);

      //Format the SubjectPublicKeyInfo structure
      error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
         (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //Public keys are encoded using the "PUBLIC KEY" label (see RFC 7468,
         //section 13)
         error = pemEncodeFile(output, length, "PUBLIC KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export a DSA private key to PEM format
 * @param[in] privateKey DSA private key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (PKCS #8 format only)
 * @return Error code
 **/

error_t pemExportDsaPrivateKey(const DsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format)
{
#if (DSA_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check output format
   if(format == PEM_PRIVATE_KEY_FORMAT_PKCS8 ||
      format == PEM_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      size_t n;
      uint8_t *p;
      Asn1Tag tag;

      //Point to the buffer where to write the PrivateKeyInfo structure
      p = (uint8_t *) output;
      //Total length of the PrivateKeyInfo structure
      length = 0;

      //Format Version field (refer to RFC 5208, section 5)
      error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);

      //Check status code
      if(!error)
      {
         X509SubjectPublicKeyInfo publicKeyInfo;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Clear the SubjectPublicKeyInfo structure
         osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

         //The PrivateKeyAlgorithm identifies the private-key algorithm
         publicKeyInfo.oid.value = DSA_OID;
         publicKeyInfo.oid.length = sizeof(DSA_OID);

         //Format PrivateKeyAlgorithm field
         error = x509FormatAlgoId(&publicKeyInfo, &privateKey->params,
            p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Format PrivateKey field
         error = pkcs8FormatDsaPrivateKey(privateKey, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Update the length of the PrivateKeyInfo structure
         length += n;

         //The PrivateKeyInfo structure is encapsulated within a sequence
         tag.constructed = TRUE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_SEQUENCE;
         tag.length = length;

         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, (uint8_t *) output, &n);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the PrivateKeyInfo structure
         length = tag.totalLength;

         //Unencrypted PKCS #8 private keys are encoded using the "PRIVATE KEY"
         //label (refer to RFC 7468, section 10)
         error = pemEncodeFile(output, length, "PRIVATE KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EC public key to PEM format
 * @param[in] publicKey EC public key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (RFC 7468 format only)
 * @return Error code
 **/

error_t pemExportEcPublicKey(const EcPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(publicKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Check output format
   if(format == PEM_PUBLIC_KEY_FORMAT_RFC7468 ||
      format == PEM_PUBLIC_KEY_FORMAT_DEFAULT)
   {
      X509SubjectPublicKeyInfo publicKeyInfo;

      //Clear the SubjectPublicKeyInfo structure
      osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

      //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
      //structure (refer to RFC 7468, section 13)
      publicKeyInfo.oid.value = EC_PUBLIC_KEY_OID;
      publicKeyInfo.oid.length = sizeof(EC_PUBLIC_KEY_OID);
      publicKeyInfo.ecParams.namedCurve.value = publicKey->curve->oid;
      publicKeyInfo.ecParams.namedCurve.length = publicKey->curve->oidSize;

      //Format the SubjectPublicKeyInfo structure
      error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
         (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //Public keys are encoded using the "PUBLIC KEY" label (see RFC 7468,
         //section 13)
         error = pemEncodeFile(output, length, "PUBLIC KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EC private key to PEM format
 * @param[in] privateKey EC private key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (RFC 5915 or PKCS #8 format)
 * @return Error code
 **/

error_t pemExportEcPrivateKey(const EcPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format)
{
#if (EC_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Check output format
   if(format == PEM_PRIVATE_KEY_FORMAT_RFC5915)
   {
      //Format ECPrivateKey structure
      error = x509ExportEcPrivateKey(privateKey->curve, privateKey,
         &privateKey->q, (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //The Base64 encoding of the DER-encoded ECPrivateKey object is
         //sandwiched between "-----BEGIN EC PRIVATE KEY-----" and
         //"-----END EC PRIVATE KEY-----" (refer to RFC 5915, section 4)
         error = pemEncodeFile(output, length, "EC PRIVATE KEY", output,
            written);
      }
   }
   else if(format == PEM_PRIVATE_KEY_FORMAT_PKCS8 ||
      format == PEM_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      size_t n;
      uint8_t *p;
      Asn1Tag tag;

      //Point to the buffer where to write the PrivateKeyInfo structure
      p = (uint8_t *) output;
      //Total length of the PrivateKeyInfo structure
      length = 0;

      //Format Version field (refer to RFC 5208, section 5)
      error = asn1WriteInt32(PKCS8_VERSION_1, FALSE, p, &n);

      //Check status code
      if(!error)
      {
         X509SubjectPublicKeyInfo publicKeyInfo;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Clear the SubjectPublicKeyInfo structure
         osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

         //The PrivateKeyAlgorithm identifies the private-key algorithm
         publicKeyInfo.oid.value = EC_PUBLIC_KEY_OID;
         publicKeyInfo.oid.length = sizeof(EC_PUBLIC_KEY_OID);
         publicKeyInfo.ecParams.namedCurve.value = privateKey->curve->oid;
         publicKeyInfo.ecParams.namedCurve.length = privateKey->curve->oidSize;

         //Format PrivateKeyAlgorithm field
         error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Format PrivateKey field
         error = pkcs8FormatEcPrivateKey(privateKey, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Update the length of the PrivateKeyInfo structure
         length += n;

         //The PrivateKeyInfo structure is encapsulated within a sequence
         tag.constructed = TRUE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_SEQUENCE;
         tag.length = length;

         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, (uint8_t *) output, &n);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the PrivateKeyInfo structure
         length = tag.totalLength;

         //Unencrypted PKCS #8 private keys are encoded using the "PRIVATE KEY"
         //label (refer to RFC 7468, section 10)
         error = pemEncodeFile(output, length, "PRIVATE KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EdDSA public key to PEM format
 * @param[in] publicKey EdDSA public key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (RFC 7468 format only)
 * @return Error code
 **/

error_t pemExportEddsaPublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, PemPublicKeyFormat format)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(publicKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Check output format
   if(format == PEM_PUBLIC_KEY_FORMAT_RFC7468 ||
      format == PEM_PUBLIC_KEY_FORMAT_DEFAULT)
   {
      X509SubjectPublicKeyInfo publicKeyInfo;

      //Clear the SubjectPublicKeyInfo structure
      osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

      //The ASN.1 encoded data of the public key is the SubjectPublicKeyInfo
      //structure (refer to RFC 7468, section 13)
      publicKeyInfo.oid.value = publicKey->curve->oid;
      publicKeyInfo.oid.length = publicKey->curve->oidSize;

      //Format the SubjectPublicKeyInfo structure
      error = x509FormatSubjectPublicKeyInfo(&publicKeyInfo, publicKey, NULL,
         (uint8_t *) output, &length);

      //Check status code
      if(!error)
      {
         //Public keys are encoded using the "PUBLIC KEY" label (see RFC 7468,
         //section 13)
         error = pemEncodeFile(output, length, "PUBLIC KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an EdDSA private key to PEM format
 * @param[in] privateKey EdDSA private key
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] written Length of the resulting PEM string
 * @param[in] format Desired output format (PKCS #8 v1 or v2 format)
 * @return Error code
 **/

error_t pemExportEddsaPrivateKey(const EddsaPrivateKey *privateKey,
   char_t *output, size_t *written, PemPrivateKeyFormat format)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   size_t length;

   //Check parameters
   if(privateKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Check output format
   if(format == PEM_PRIVATE_KEY_FORMAT_PKCS8 ||
      format == PEM_PRIVATE_KEY_FORMAT_PKCS8_V2 ||
      format == PEM_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      size_t n;
      uint8_t *p;
      int32_t version;
      Asn1Tag tag;

      //Point to the buffer where to write the PrivateKeyInfo structure
      p = (uint8_t *) output;
      //Total length of the PrivateKeyInfo structure
      length = 0;

      //The Version field identifies the version of OneAsymmetricKey. If
      //publicKey is present, then version is set to v2 else version is set
      //to v1 (refer to RFC 5958, section 2)
      if(format == PEM_PRIVATE_KEY_FORMAT_PKCS8_V2 &&
         privateKey->q.curve != NULL)
      {
         version = PKCS8_VERSION_2;
      }
      else
      {
         version = PKCS8_VERSION_1;
      }

      //Format Version field
      error = asn1WriteInt32(version, FALSE, p, &n);

      //Check status code
      if(!error)
      {
         X509SubjectPublicKeyInfo publicKeyInfo;

         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Clear the SubjectPublicKeyInfo structure
         osMemset(&publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

         //The PrivateKeyAlgorithm identifies the private-key algorithm
         publicKeyInfo.oid.value = privateKey->curve->oid;
         publicKeyInfo.oid.length = privateKey->curve->oidSize;

         //Format PrivateKeyAlgorithm field
         error = x509FormatAlgoId(&publicKeyInfo, NULL, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //Format PrivateKey field
         error = pkcs8FormatEddsaPrivateKey(privateKey, p, &n);
      }

      //Check status code
      if(!error)
      {
         //Advance data pointer
         ASN1_INC_POINTER(p, n);
         length += n;

         //The publicKey field is optional
         if(format == PEM_PRIVATE_KEY_FORMAT_PKCS8_V2 &&
            privateKey->q.curve != NULL)
         {
            //Format publicKey field
            error = pkcs8FormatEddsaPublicKey(&privateKey->q, p, &n);
            //Any error to report?
            if(error)
               return error;

            //Update the length of the PrivateKeyInfo structure
            length += n;
         }
      }

      //Check status code
      if(!error)
      {
         //The PrivateKeyInfo structure is encapsulated within a sequence
         tag.constructed = TRUE;
         tag.objClass = ASN1_CLASS_UNIVERSAL;
         tag.objType = ASN1_TYPE_SEQUENCE;
         tag.length = length;

         //Write the corresponding ASN.1 tag
         error = asn1InsertHeader(&tag, (uint8_t *) output, &n);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the PrivateKeyInfo structure
         length = tag.totalLength;

         //Unencrypted PKCS #8 private keys are encoded using the "PRIVATE KEY"
         //label (refer to RFC 7468, section 10)
         error = pemEncodeFile(output, length, "PRIVATE KEY", output, written);
      }
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
