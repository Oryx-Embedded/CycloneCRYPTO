/**
 * @file ecdsa.c
 * @brief ECDSA (Elliptic Curve Digital Signature Algorithm)
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
#include "ecc/ecdsa.h"
#include "ecc/ec_misc.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (ECDSA_SUPPORT == ENABLED)

//ECDSA with SHA-1 OID (1.2.840.10045.4.1)
const uint8_t ECDSA_WITH_SHA1_OID[7] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};
//ECDSA with SHA-224 OID (1.2.840.10045.4.3.1)
const uint8_t ECDSA_WITH_SHA224_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01};
//ECDSA with SHA-256 OID (1.2.840.10045.4.3.2)
const uint8_t ECDSA_WITH_SHA256_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
//ECDSA with SHA-384 OID (1.2.840.10045.4.3.3)
const uint8_t ECDSA_WITH_SHA384_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
//ECDSA with SHA-512 OID (1.2.840.10045.4.3.4)
const uint8_t ECDSA_WITH_SHA512_OID[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};
//ECDSA with SHA-3-224 OID (2.16.840.1.101.3.4.3.9)
const uint8_t ECDSA_WITH_SHA3_224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09};
//ECDSA with SHA-3-256 OID (2.16.840.1.101.3.4.3.10)
const uint8_t ECDSA_WITH_SHA3_256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0A};
//ECDSA with SHA-3-384 OID (2.16.840.1.101.3.4.3.11)
const uint8_t ECDSA_WITH_SHA3_384_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0B};
//ECDSA with SHA-3-512 OID (2.16.840.1.101.3.4.3.12)
const uint8_t ECDSA_WITH_SHA3_512_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0C};
//ECDSA with SHAKE128 OID (1.3.6.1.5.5.7.6.32)
const uint8_t ECDSA_WITH_SHAKE128_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20};
//ECDSA with SHAKE256 OID (1.3.6.1.5.5.7.6.33)
const uint8_t ECDSA_WITH_SHAKE256_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x21};


/**
 * @brief Initialize an ECDSA signature
 * @param[in] signature Pointer to the ECDSA signature to initialize
 **/

void ecdsaInitSignature(EcdsaSignature *signature)
{
   //Initialize (R, S) integer pair
   ecScalarSetInt(signature->r, 0, EC_MAX_ORDER_SIZE);
   ecScalarSetInt(signature->s, 0, EC_MAX_ORDER_SIZE);
}


/**
 * @brief Release an ECDSA signature
 * @param[in] signature Pointer to the ECDSA signature to free
 **/

void ecdsaFreeSignature(EcdsaSignature *signature)
{
   //Release (R, S) integer pair
   ecScalarSetInt(signature->r, 0, EC_MAX_ORDER_SIZE);
   ecScalarSetInt(signature->s, 0, EC_MAX_ORDER_SIZE);
}


/**
 * @brief Import an ECDSA signature
 * @param[out] signature ECDSA signature
 * @param[in] curve Elliptic curve parameters
 * @param[in] input Pointer to the octet string
 * @param[in] length Length of the octet string, in bytes
 * @param[in] format ECDSA signature format (ASN.1 or raw format)
 * @return Error code
 **/

error_t ecdsaImportSignature(EcdsaSignature *signature, const EcCurve *curve,
   const uint8_t *input, size_t length, EcdsaSignatureFormat format)
{
   error_t error;
   size_t n;

   //Check parameters
   if(signature == NULL || curve == NULL || input == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get the length of the order, in bytes
   n = (curve->orderSize + 7) / 8;

   //Debug message
   TRACE_DEBUG("Importing ECDSA signature...\r\n");

   //Dump ECDSA signature
   TRACE_DEBUG("  signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", input, length);

   //Check the format of the ECDSA signature
   if(format == ECDSA_SIGNATURE_FORMAT_ASN1)
   {
      Asn1Tag tag;

      //Display ASN.1 structure
      error = asn1DumpObject(input, length, 0);
      //Any error to report?
      if(error)
         return error;

      //Read the contents of the ASN.1 structure
      error = asn1ReadSequence(input, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Malformed ECDSA signature?
      if(length != tag.totalLength)
         return ERROR_INVALID_SYNTAX;

      //Point to the first field
      input = tag.value;
      length = tag.length;

      //Read the integer R
      error = asn1ReadTag(input, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         return error;

      //Make sure R is a positive integer
      if(tag.length == 0 || (tag.value[0] & 0x80) != 0)
         return ERROR_INVALID_SYNTAX;

      //Convert the octet string to an integer
      error = ecScalarImport(signature->r, EC_MAX_ORDER_SIZE, tag.value,
         tag.length, EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;

      //Point to the next field
      input += tag.totalLength;
      length -= tag.totalLength;

      //Read the integer S
      error = asn1ReadTag(input, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         return error;

      //Make sure S is a positive integer
      if(tag.length == 0 || (tag.value[0] & 0x80) != 0)
         return ERROR_INVALID_SYNTAX;

      //Convert the octet string to an integer
      error = ecScalarImport(signature->s, EC_MAX_ORDER_SIZE, tag.value,
         tag.length, EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;

      //Malformed ECDSA signature?
      if(length != tag.totalLength)
         return ERROR_INVALID_SYNTAX;

      //Dump (R, S) integer pair
      TRACE_DEBUG("  r:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", signature->r, EC_MAX_ORDER_SIZE);
      TRACE_DEBUG("  s:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", signature->s, EC_MAX_ORDER_SIZE);
   }
   else if(format == ECDSA_SIGNATURE_FORMAT_RAW)
   {
      //Check the length of the octet string
      if(length != (n * 2))
         return ERROR_INVALID_LENGTH;

      //Convert R to an integer
      error = ecScalarImport(signature->r, EC_MAX_ORDER_SIZE, input, n,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;

      //Convert S to an integer
      error = ecScalarImport(signature->s, EC_MAX_ORDER_SIZE,
         input + n, n, EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;
   }
   else if(format == ECDSA_SIGNATURE_FORMAT_RAW_R)
   {
      //Convert R to an integer
      error = ecScalarImport(signature->r, EC_MAX_ORDER_SIZE, input, length,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;
   }
   else if(format == ECDSA_SIGNATURE_FORMAT_RAW_S)
   {
      //Convert S to an integer
      error = ecScalarImport(signature->s, EC_MAX_ORDER_SIZE, input, length,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //Invalid format
      return ERROR_INVALID_PARAMETER;
   }

   //Save elliptic curve parameters
   signature->curve = curve;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Export an ECDSA signature
 * @param[in] signature ECDSA signature
 * @param[out] output Pointer to the octet string (optional parameter)
 * @param[out] written Length of the resulting octet string, in bytes
 * @param[in] format ECDSA signature format (ASN.1 or raw format)
 * @return Error code
 **/

error_t ecdsaExportSignature(const EcdsaSignature *signature, uint8_t *output,
   size_t *written, EcdsaSignatureFormat format)
{
   error_t error;
   size_t k;
   size_t n;
   size_t length;
   size_t orderLen;
   uint8_t *p;
   Asn1Tag tag;

   //Check parameters
   if(signature == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(signature->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get the length of the order, in words
   orderLen = (signature->curve->orderSize + 31) / 32;

   //Debug message
   TRACE_DEBUG("Exporting ECDSA signature...\r\n");

   //Dump (R, S) integer pair
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", signature->r, orderLen);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", signature->s, orderLen);

   //Check the format of the ECDSA signature
   if(format == ECDSA_SIGNATURE_FORMAT_ASN1)
   {
      //Point to the buffer where to write the ASN.1 structure
      p = output;
      //Length of the ASN.1 structure
      length = 0;

      //R is always  encoded in the smallest possible number of octets
      k = ecScalarGetBitLength(signature->r, orderLen) / 8 + 1;

      //R is represented by an integer
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_INTEGER;
      tag.length = k;

      //Write the corresponding ASN.1 tag
      error = asn1WriteHeader(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //If the output parameter is NULL, then the function calculates the
      //length of the ASN.1 structure without copying any data
      if(p != NULL)
      {
         //Convert R to an octet string
         error = ecScalarExport(signature->r, EC_MAX_ORDER_SIZE, p, k,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
         //Any error to report?
         if(error)
            return error;
      }

      //Advance data pointer
      ASN1_INC_POINTER(p, k);
      length += k;

      //S is always  encoded in the smallest possible number of octets
      k = ecScalarGetBitLength(signature->s, orderLen) / 8 + 1;

      //S is represented by an integer
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_INTEGER;
      tag.length = k;

      //Write the corresponding ASN.1 tag
      error = asn1WriteHeader(&tag, FALSE, p, &n);
      //Any error to report?
      if(error)
         return error;

      //Advance data pointer
      ASN1_INC_POINTER(p, n);
      length += n;

      //If the output parameter is NULL, then the function calculates the
      //length of the ASN.1 structure without copying any data
      if(p != NULL)
      {
         //Convert S to an octet string
         error = ecScalarExport(signature->s, EC_MAX_ORDER_SIZE, p, k,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
         //Any error to report?
         if(error)
            return error;
      }

      //Advance data pointer
      ASN1_INC_POINTER(p, k);
      length += k;

      //The (R, S) integer pair is encapsulated within a sequence
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_SEQUENCE;
      tag.length = length;

      //Write the corresponding ASN.1 tag
      error = asn1InsertHeader(&tag, output, &n);
      //Any error to report?
      if(error)
         return error;

      //Total length of the ASN.1 structure
      *written = length + n;
   }
   else if(format == ECDSA_SIGNATURE_FORMAT_RAW)
   {
      //Get the length of the order, in bytes
      n = (signature->curve->orderSize + 7) / 8;

      //If the output parameter is NULL, then the function calculates the
      //length of the octet string without copying any data
      if(output != NULL)
      {
         //Convert R to an octet string
         error = ecScalarExport(signature->r, (n + 3) / 4, output, n,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
         //Any error to report?
         if(error)
            return error;

         //Convert S to an octet string
         error = ecScalarExport(signature->s, (n + 3) / 4, output + n, n,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
         //Any error to report?
         if(error)
            return error;
      }

      //Length of the resulting octet string
      *written = 2 * n;
   }
   else if(format == ECDSA_SIGNATURE_FORMAT_RAW_R)
   {
      //Get the length of the order, in bytes
      n = (signature->curve->orderSize + 7) / 8;

      //If the output parameter is NULL, then the function calculates the
      //length of the octet string without copying any data
      if(output != NULL)
      {
         //Convert R to an octet string
         error = ecScalarExport(signature->r, (n + 3) / 4, output, n,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
         //Any error to report?
         if(error)
            return error;
      }

      //Length of the resulting octet string
      *written = n;
   }
   else if(format == ECDSA_SIGNATURE_FORMAT_RAW_S)
   {
      //Get the length of the order, in bytes
      n = (signature->curve->orderSize + 7) / 8;

      //If the output parameter is NULL, then the function calculates the
      //length of the octet string without copying any data
      if(output != NULL)
      {
         //Convert S to an octet string
         error = ecScalarExport(signature->s, (n + 3) / 4, output, n,
            EC_SCALAR_FORMAT_BIG_ENDIAN);
         //Any error to report?
         if(error)
            return error;
      }

      //Length of the resulting octet string
      *written = n;
   }
   else
   {
      //Invalid format
      return ERROR_INVALID_PARAMETER;
   }

   //Dump ECDSA signature
   if(output != NULL)
   {
      TRACE_DEBUG("  signature:\r\n");
      TRACE_DEBUG_ARRAY("    ", output, *written);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

__weak_func error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo,
   void *prngContext, const EcPrivateKey *privateKey, const uint8_t *digest,
   size_t digestLen, EcdsaSignature *signature)
{
   error_t error;
   uint_t n;
   uint_t pLen;
   uint_t qLen;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   EcdsaGenerateSignatureState *state;
#else
   EcdsaGenerateSignatureState state[1];
#endif

   //Check parameters
   if(privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get the length of the modulus, in words
   pLen = (privateKey->curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   qLen = (privateKey->curve->orderSize + 31) / 32;

   //Debug message
   TRACE_DEBUG("ECDSA signature generation...\r\n");
   TRACE_DEBUG("  curve: %s\r\n", privateKey->curve->name);
   TRACE_DEBUG("  private key:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", privateKey->d, qLen);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(EcdsaGenerateSignatureState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(EcdsaGenerateSignatureState));

   //Initialize (R, S) integer pair
   ecScalarSetInt(signature->r, 0, EC_MAX_ORDER_SIZE);
   ecScalarSetInt(signature->s, 0, EC_MAX_ORDER_SIZE);

   //Generate a random number k such as 0 < k < q - 1
   error = ecScalarRand(privateKey->curve, state->k, prngAlgo, prngContext);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  k:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->k, qLen);

      //Let N be the bit length of q
      n = privateKey->curve->orderSize;
      //Compute N = MIN(N, outlen)
      n = MIN(n, digestLen * 8);

      //Convert the digest to an integer
      error = ecScalarImport(state->z, qLen, digest, (n + 7) / 8,
         EC_SCALAR_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Keep the leftmost N bits of the hash value
      if((n % 8) != 0)
      {
         ecScalarShiftRight(state->z, state->z, 8 - (n % 8), qLen);
      }

      //Debug message
      TRACE_DEBUG("  z:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->z, qLen);

      //Compute R1 = (x1, y1) = k.G
      error = ecMulRegular(privateKey->curve, &state->r1, state->k,
         &privateKey->curve->g);
   }

   //Check status code
   if(!error)
   {
      //Convert R1 to affine representation
      error = ecAffinify(privateKey->curve, &state->r1, &state->r1);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  x1:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->r1.x, pLen);
      TRACE_DEBUG("  y1:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->r1.y, pLen);

      //Compute r = x1 mod q
      ecScalarMod(signature->r, state->r1.x, pLen, privateKey->curve->q, qLen);
      //Compute k ^ -1 mod q
      ecScalarInvMod(privateKey->curve, state->k, state->k);

      //Compute s = k ^ -1 * (z + x * r) mod q
      ecScalarMulMod(privateKey->curve, signature->s, privateKey->d, signature->r);
      ecScalarAddMod(privateKey->curve, signature->s, signature->s, state->z);
      ecScalarMulMod(privateKey->curve, signature->s, signature->s, state->k);

      //Save elliptic curve parameters
      signature->curve = privateKey->curve;

      //Debug message
      TRACE_DEBUG("  r:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", signature->r, qLen);
      TRACE_DEBUG("  s:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", signature->s, qLen);
   }

   //Erase working state
   osMemset(state, 0, sizeof(EcdsaGenerateSignatureState));

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release working state
   cryptoFreeMem(state);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief ECDSA signature verification
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

__weak_func error_t ecdsaVerifySignature(const EcPublicKey *publicKey,
   const uint8_t *digest, size_t digestLen, const EcdsaSignature *signature)
{
   error_t error;
   uint_t n;
   uint_t pLen;
   uint_t qLen;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   EcdsaVerifySignatureState *state;
#else
   EcdsaVerifySignatureState state[1];
#endif

   //Check parameters
   if(publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(publicKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get the length of the modulus, in words
   pLen = (publicKey->curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   qLen = (publicKey->curve->orderSize + 31) / 32;

   //Debug message
   TRACE_DEBUG("ECDSA signature verification...\r\n");
   TRACE_DEBUG("  curve: %s\r\n", publicKey->curve->name);
   TRACE_DEBUG("  public key X:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", publicKey->q.x, pLen);
   TRACE_DEBUG("  public key Y:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", publicKey->q.y, pLen);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", signature->r, qLen);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_EC_SCALAR("    ", signature->s, qLen);

   //Verify that the public key is on the curve
   if(!ecIsPointAffine(publicKey->curve, &publicKey->q))
   {
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < r < q
   if(ecScalarCompInt(signature->r, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->r, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(ecScalarCompInt(signature->s, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->s, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate working state
   state = cryptoAllocMem(sizeof(EcdsaVerifySignatureState));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize working state
   osMemset(state, 0, sizeof(EcdsaVerifySignatureState));

   //Let N be the bit length of q
   n = publicKey->curve->orderSize;
   //Compute N = MIN(N, outlen)
   n = MIN(n, digestLen * 8);

   //Convert the digest to an integer
   error = ecScalarImport(state->z, qLen, digest, (n + 7) / 8,
      EC_SCALAR_FORMAT_BIG_ENDIAN);

   //Check status code
   if(!error)
   {
      //Keep the leftmost N bits of the hash value
      if((n % 8) != 0)
      {
         ecScalarShiftRight(state->z, state->z, 8 - (n % 8), qLen);
      }

      //Compute w = s ^ -1 mod q
      ecScalarInvMod(publicKey->curve, state->w, signature->s);

      //Compute u1 = z * w mod q
      ecScalarMulMod(publicKey->curve, state->u1, state->z, state->w);
      //Compute u2 = r * w mod q
      ecScalarMulMod(publicKey->curve, state->u2, signature->r, state->w);

      //Convert the public key to projective representation
      ecProjectify(publicKey->curve, &state->v1, &publicKey->q);

      //Compute V0 = (x0, y0) = u1.G + u2.Q
      error = ecTwinMul(publicKey->curve, &state->v0, state->u1,
         &publicKey->curve->g, state->u2, &state->v1);
   }

   //Check status code
   if(!error)
   {
      //Convert V0 to affine representation
      error = ecAffinify(publicKey->curve, &state->v0, &state->v0);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  x0:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->v0.x, pLen);
      TRACE_DEBUG("  y0:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->v0.y, pLen);

      //Compute v = x0 mod q
      ecScalarMod(state->v, state->v0.x, pLen, publicKey->curve->q, qLen);

      //Debug message
      TRACE_DEBUG("  v:\r\n");
      TRACE_DEBUG_EC_SCALAR("    ", state->v, qLen);

      //If v = r, then the signature is verified. If v does not equal r, then the
      //message or the signature may have been modified
      if(ecScalarComp(state->v, signature->r, qLen) == 0)
      {
         error = NO_ERROR;
      }
      else
      {
         error = ERROR_INVALID_SIGNATURE;
      }
   }

   //Erase working state
   osMemset(state, 0, sizeof(EcdsaVerifySignatureState));

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Release working state
   cryptoFreeMem(state);
#endif

   //Return status code
   return error;
}

#endif
