/**
 * @file ecrdsa.c
 * @brief ECRDSA (Elliptic Curve Russian Digital Signature Algorithm)
 *
 * Elliptic Curve (Russian) Digital Signature Algorithm for Cryptographic API
 *
 * Copyright (c) 2024 Valery Novikov <novikov.val@gmail.com>
 *
 * References:
 * GOST 34.10-2018, GOST R 34.10-2012, RFC 7091, ISO/IEC 14888-3:2018.
 *
 * Historical references:
 * GOST R 34.10-2001, RFC 4357, ISO/IEC 14888-3:2006/Amd 1:2010.
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
 * @author Valery Novikov <novikov.val@gmail.com>
 * @version 2.4.0
 **/

/**
 * TODO: 
 *       ecrdsaWriteSignature
 *       ecrdsaReadSignature
 *       OIDs
 *       NIST Curves
 *       X509 support
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL//TRACE_LEVEL_VERBOSE//CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "ecc/ecrdsa.h"
#include "mpi/mpi.h"
#include "encoding/asn1.h"
#include "debug.h"

//Check crypto library configuration
#if (ECRDSA_SUPPORT == ENABLED)
/* TODO: временно для порта
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
*/

static inline error_t ecrdsaGenerateSignatureStep4(const EcDomainParameters *params, const Mpi *k, EcPoint *C, EcrdsaSignature *signature)
{
	error_t error;
	// Step 4: Compute the point of the elliptic curve C = kP and determine r = Xc (mod q), where – Xc is the coordinate of point C. If r = 0, then go back to step 3.
	EC_CHECK(ecMult(params, C, k, &params->g));
	EC_CHECK(ecAffinify(params, C, C));
	MPI_CHECK(mpiMod(&signature->r, &C->x, &params->q));
	return NO_ERROR;
end:
	return error;
}

static inline error_t ecrdsaGenerateSignatureStep5(const Mpi *d, const Mpi *e, Mpi *k, const Mpi *q, EcrdsaSignature *signature)
{
	error_t error;
	// Step 5: Compute the value of s ≡ (rd + ke)(mod q). If s = 0, then go back to step 3.
	MPI_CHECK(mpiMul(&signature->s, &signature->r, d));
	MPI_CHECK(mpiMul(k, k, e));
	MPI_CHECK(mpiAdd(&signature->s, &signature->s, k));
	MPI_CHECK(mpiMod(&signature->s, &signature->s, q));
	return NO_ERROR;
end:
	return error;
}

static inline error_t ecrdsaVerifySignatureFinal(const EcDomainParameters *params, const EcPoint *Q, const Mpi *e, EcrdsaSignature *signature)
{
	error_t error = NO_ERROR;
	Mpi v;
	Mpi z1;
	Mpi z2;
	EcPoint C;

	//Initialize multiple precision integers
	mpiInit(&v);
	mpiInit(&z1);
	mpiInit(&z2);
	//Initialize EC points
	ecInit(&C);

	// Step 4: Compute v = e ^ -1 mod q
	MPI_CHECK(mpiInvMod(&v, e, &params->q));
	// Step 5: Compute z1 = s * v mod q
	MPI_CHECK(mpiMulMod(&z1, &signature->s, &v, &params->q));
	// Compute z2 = -r * v mod q
	signature->r.sign = -1;
	MPI_CHECK(mpiMulMod(&z2, &signature->r, &v, &params->q));
	signature->r.sign = 1;
	// Step 6: Compute C = z1 * G + z2 * Q
	EC_CHECK(ecProjectify(params, &C, Q));
	EC_CHECK(ecTwinMult(params, &C, &z1, &params->g, &z2, Q));
	EC_CHECK(ecAffinify(params, &C, &C));
	// Debug message
	TRACE_DEBUG("  Cx:\r\n");
	TRACE_DEBUG_MPI("    ", &C.x);
	TRACE_DEBUG("  Cy:\r\n");
	TRACE_DEBUG_MPI("    ", &C.y);
	// Step 7: Compute R = Cx mod q
	MPI_CHECK(mpiMod(&v, &C.x, &params->q));

	//Debug message
	TRACE_DEBUG("  R:\r\n");
	TRACE_DEBUG_MPI("    ", &v);

	//If v = r, then the signature is verified. If v does not equal r,
	//then the message or the signature may have been modified
	if (mpiComp(&v, &signature->r))
		error = ERROR_INVALID_SIGNATURE;
end:
	return error;
}

/**
 * @brief Initialize an ECRDSA signature
 * @param[in] signature Pointer to the ECRDSA signature to initialize
 **/

void ecrdsaInitSignature(EcrdsaSignature *signature)
{
   //Initialize multiple precision integers
   mpiInit(&signature->r);
   mpiInit(&signature->s);
}


/**
 * @brief Release an ECRDSA signature
 * @param[in] signature Pointer to the ECRDSA signature to free
 **/

void ecrdsaFreeSignature(EcrdsaSignature *signature)
{
   //Release multiple precision integers
   mpiFree(&signature->r);
   mpiFree(&signature->s);
}


/**
 * @brief Encode ECRDSA signature using ASN.1
 * @param[in] signature (R, S) integer pair
 * @param[out] data Pointer to the buffer where to store the resulting ASN.1 structure
 * @param[out] length Length of the ASN.1 structure
 * @return Error code
 **/

error_t ecrdsaWriteSignature(const EcrdsaSignature *signature, uint8_t *data,
   size_t *length)
{
   error_t error;
   size_t k;
   size_t n;
   size_t rLen;
   size_t sLen;
   Asn1Tag tag;

   //Debug message
   TRACE_INFO("Writing ECRDSA signature...\r\n");

   //Dump (R, S) integer pair
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

   //Calculate the length of R
   rLen = mpiGetByteLength(&signature->r);
   //Calculate the length of S
   sLen = mpiGetByteLength(&signature->s);

   //Make sure the (R, S) integer pair is valid
   if(rLen == 0 || sLen == 0)
      return ERROR_INVALID_LENGTH;

   //R and S are always encoded in the smallest possible number of octets
   if(mpiGetBitValue(&signature->r, (rLen * 8) - 1))
   {
      rLen++;
   }

   if(mpiGetBitValue(&signature->s, (sLen * 8) - 1))
   {
      sLen++;
   }

   //The first pass computes the length of the ASN.1 sequence
   n = 0;

   //The parameter R is encapsulated within an ASN.1 structure
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = rLen;
   tag.value = NULL;

   //Compute the length of the corresponding ASN.1 structure
   error = asn1WriteTag(&tag, FALSE, NULL, NULL);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the ASN.1 sequence
   n += tag.totalLength;

   //The parameter S is encapsulated within an ASN.1 structure
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = sLen;
   tag.value = NULL;

   //Compute the length of the corresponding ASN.1 structure
   error = asn1WriteTag(&tag, FALSE, NULL, NULL);
   //Any error to report?
   if(error)
      return error;

   //Update the length of the ASN.1 sequence
   n += tag.totalLength;

   //The second pass encodes the ASN.1 structure
   k = 0;

   //The (R, S) integer pair is encapsulated within a sequence
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = n;
   tag.value = NULL;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, data + k, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += n;

   //Encode the parameter R using ASN.1
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = rLen;
   tag.value = NULL;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, data + k, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += n;

   //Convert R to an octet string
   error = mpiWriteRaw(&signature->r, data + k, rLen);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += rLen;

   //Encode the parameter S using ASN.1
   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_INTEGER;
   tag.length = sLen;
   tag.value = NULL;

   //Write the corresponding ASN.1 tag
   error = asn1WriteTag(&tag, FALSE, data + k, &n);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += n;

   //Convert S to an octet string
   error = mpiWriteRaw(&signature->s, data + k, sLen);
   //Any error to report?
   if(error)
      return error;

   //Advance write pointer
   k += sLen;

   //Dump ECRDSA signature
   TRACE_DEBUG("  signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", data, k);

   //Total length of the ASN.1 structure
   *length = k;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read an ASN.1 encoded ECRDSA signature
 * @param[in] data Pointer to the ASN.1 structure to decode
 * @param[in] length Length of the ASN.1 structure
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecrdsaReadSignature(const uint8_t *data, size_t length, EcrdsaSignature *signature)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("Reading ECRDSA signature...\r\n");

   //Dump ECRDSA signature
   TRACE_DEBUG("  signature:\r\n");
   TRACE_DEBUG_ARRAY("    ", data, length);

   //Start of exception handling block
   do
   {
      //Display ASN.1 structure
      error = asn1DumpObject(data, length, 0);
      //Any error to report?
      if(error)
         break;

      //Read the contents of the ASN.1 structure
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Malformed ECRDSA signature?
      if(length != tag.totalLength)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the first field
      data = tag.value;
      length = tag.length;

      //Read the parameter R
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         break;

      //Make sure R is a positive integer
      if(tag.length == 0 || (tag.value[0] & 0x80) != 0)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Convert the octet string to a multiple precision integer
      error = mpiReadRaw(&signature->r, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the parameter S
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         break;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         break;

      //Make sure S is a positive integer
      if(tag.length == 0 || (tag.value[0] & 0x80) != 0)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Convert the octet string to a multiple precision integer
      error = mpiReadRaw(&signature->s, tag.value, tag.length);
      //Any error to report?
      if(error)
         break;

      //Malformed ECRDSA signature?
      if(length != tag.totalLength)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Dump (R, S) integer pair
      TRACE_DEBUG("  r:\r\n");
      TRACE_DEBUG_MPI("    ", &signature->r);
      TRACE_DEBUG("  s:\r\n");
      TRACE_DEBUG_MPI("    ", &signature->s);

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecrdsaFreeSignature(signature);
   }

   //Return status code
   return error;
}


/**
 * @brief ECRDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

__weak_func error_t ecrdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, const EcPrivateKey *privateKey,
   const uint8_t *digest, size_t digestLen, EcrdsaSignature *signature)
{
   error_t error;
   uint_t n;
   Mpi e;
   Mpi k;
   EcPoint C;

   // Check parameters
   if (params == NULL || privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("ECRDSA signature generation...\r\n");
   TRACE_DEBUG("  private key:\r\n");
   TRACE_DEBUG_MPI("    ", &privateKey->d);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);

   // Initialize multiple precision integers
   mpiInit(&e);
   mpiInit(&k);
   // Initialize EC point
   ecInit(&C);

   // Step 1: Compute hash (h) of the message (passed as input) */ 

   // Step 2: Compute the integer a, the binary representation of which is the vector h, and determine e = a (mod q)
   // Let N be the bit length of q
   n = mpiGetBitLength(&params->q);
   // Compute N = MIN(N, outlen)
   n = MIN(n, digestLen * 8);
   // Convert the digest to a multiple precision integer ( h(M) -> a )
   MPI_CHECK(mpiReadRaw(&e, digest, (n + 7) / 8));
   // Keep the leftmost N bits of the hash value
   if ((n % 8) != 0)
	   MPI_CHECK(mpiShiftRight(&e, 8 - (n % 8)));
   // Compute e = a (mod q), if e = 0, to e = 1
   MPI_CHECK(mpiMod(&e, &e, &params->q));
   if (!mpiCompInt(&e, 0))
	   MPI_CHECK(mpiSetValue(&e, 1));
   // Debug message
   TRACE_DEBUG("  e:\r\n");
   TRACE_DEBUG_MPI("    ", &e);
   do {
	   do {
		   // Step 3: Generate a random number k such as 0 < k < q
		   MPI_CHECK(mpiRandRange(&k, &params->q, prngAlgo, prngContext));
		   // Debug message
		   TRACE_DEBUG("  k:\r\n");
		   TRACE_DEBUG_MPI("    ", &k);
		   // Step 4: Compute the point of the elliptic curve C = kP and determine r = Xc (mod q), where – Xc is the coordinate of point C. If r = 0, then go back to step 3.
		   EC_CHECK(ecrdsaGenerateSignatureStep4(params, &k, &C, signature));
		   // Debug message
		   TRACE_DEBUG("  r:\r\n");
		   TRACE_DEBUG_MPI("    ", &signature->r);
	   } while (!mpiCompInt(&signature->r, 0));
	   // Step 5: Compute the value of s ≡ (rd + ke)(mod q). If s = 0, then go back to step 3.
	   EC_CHECK(ecrdsaGenerateSignatureStep5(&privateKey->d, &e, &k, &params->q, signature));
	   TRACE_DEBUG("%d\n", mpiGetLength(&signature->s));
	   // Debug message
	   TRACE_DEBUG("  s:\r\n");
	   TRACE_DEBUG_MPI("    ", &signature->s);
   } while (!mpiCompInt(&signature->s, 0));
   // Dump ECRDSA signature
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);
end:
   // Release multiple precision integers
   mpiFree(&e);
   mpiFree(&k);
   // Release EC point
   ecFree(&C);
   // Clean up side effects if necessary
   if(error) {
      // Release (R, S) integer pair
      mpiFree(&signature->r);
      mpiFree(&signature->s);
   }
   // Return status code
   return error;
}


/**
 * @brief ECRDSA signature verification
 * @param[in] params EC domain parameters
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

__weak_func error_t ecrdsaVerifySignature(const EcDomainParameters *params,
   const EcPublicKey *publicKey, const uint8_t *digest, size_t digestLen,
   const EcrdsaSignature *signature)
{
   error_t error;
   uint_t n;
   Mpi e;

   //Check parameters
   if(params == NULL || publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_DEBUG("ECRDSA signature verification...\r\n");
   TRACE_DEBUG("  public key X:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.x);
   TRACE_DEBUG("  public key Y:\r\n");
   TRACE_DEBUG_MPI("    ", &publicKey->q.y);
   TRACE_DEBUG("  digest:\r\n");
   TRACE_DEBUG_ARRAY("    ", digest, digestLen);
   TRACE_DEBUG("  r:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->r);
   TRACE_DEBUG("  s:\r\n");
   TRACE_DEBUG_MPI("    ", &signature->s);

   //The verifier shall check that 0 < r < q, if the condition is violated, the signature shall be rejected as invalid
   if(mpiCompInt(&signature->r, 0) <= 0 || mpiComp(&signature->r, &params->q) >= 0)
      return ERROR_INVALID_SIGNATURE;

   //The verifier shall check that 0 < s < q, if the condition is violated, the signature shall be rejected as invalid
   if(mpiCompInt(&signature->s, 0) <= 0 || mpiComp(&signature->s, &params->q) >= 0)
      return ERROR_INVALID_SIGNATURE;

   //Initialize multiple precision integers
   mpiInit(&e);

   //Let N be the bit length of q
   n = mpiGetBitLength(&params->q);
   //Compute N = MIN(N, outlen)
   n = MIN(n, digestLen * 8);
   //Convert the digest to a multiple precision integer
   MPI_CHECK(mpiReadRaw(&e, digest, (n + 7) / 8));
   //Keep the leftmost N bits of the hash value
   if((n % 8) != 0)
      MPI_CHECK(mpiShiftRight(&e, 8 - (n % 8)));
   // Steps 4-7
   MPI_CHECK(ecrdsaVerifySignatureFinal(params, &publicKey->q, &e, (EcrdsaSignature *)signature));
end:
   //Release multiple precision integers
   mpiFree(&e);
   //Return status code
   return error;
}

#if (ECRDSA_TEST_SUPPORT == ENABLED)
#define p_RAW_1		"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x31"
#define a_RAW_1		"\x07"
#define b_RAW_1		"\x5F\xBF\xF4\x98\xAA\x93\x8C\xE7\x39\xB8\xE0\x22\xFB\xAF\xEF\x40\x56\x3F\x6E\x6A\x34\x72\xFC\x2A\x51\x4C\x0C\xE9\xDA\xE2\x3B\x7E"
#define q_RAW_1		"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x50\xFE\x8A\x18\x92\x97\x61\x54\xC5\x9C\xFC\x19\x3A\xCC\xF5\xB3"
#define GX_RAW_1	"\x02"
#define GY_RAW_1	"\x08\xE2\xA8\xA0\xE6\x51\x47\xD4\xBD\x63\x16\x03\x0E\x16\xD1\x9C\x85\xC9\x7F\x0A\x9C\xA2\x67\x12\x2B\x96\xAB\xBC\xEA\x7E\x8F\xC8"
#define k_RAW_1		"\x77\x10\x5C\x9B\x20\xBC\xD3\x12\x28\x23\xC8\xCF\x6F\xCC\x7B\x95\x6D\xE3\x38\x14\xE9\x5B\x7F\xE6\x4F\xED\x92\x45\x94\xDC\xEA\xB3"
#define e_RAW_1		"\x2D\xFB\xC1\xB3\x72\xD8\x9A\x11\x88\xC0\x9C\x52\xE0\xEE\xC6\x1F\xCE\x52\x03\x2A\xB1\x02\x2E\x8E\x67\xEC\xE6\x67\x2B\x04\x3E\xE5"
#define d_RAW_1		"\x7A\x92\x9A\xDE\x78\x9B\xB9\xBE\x10\xED\x35\x9D\xD3\x9A\x72\xC1\x1B\x60\x96\x1F\x49\x39\x7E\xEE\x1D\x19\xCE\x98\x91\xEC\x3B\x28"
#define r_RAW_1		"\x41\xAA\x28\xD2\xF1\xAB\x14\x82\x80\xCD\x9E\xD5\x6F\xED\xA4\x19\x74\x05\x35\x54\xA4\x27\x67\xB8\x3A\xD0\x43\xFD\x39\xDC\x04\x93"
#define s_RAW_1     "\x01\x45\x6C\x64\xBA\x46\x42\xA1\x65\x3C\x23\x5A\x98\xA6\x02\x49\xBC\xD6\xD3\xF7\x46\xB6\x31\xDF\x92\x80\x14\xF6\xC5\xBF\x9C\x40"
#define QX_RAW_1	"\x7F\x2B\x49\xE2\x70\xDB\x6D\x90\xD8\x59\x5B\xEC\x45\x8B\x50\xC5\x85\x85\xBA\x1D\x4E\x9B\x78\x8F\x66\x89\xDB\xD8\xE5\x6F\xD8\x0B"
#define QY_RAW_1	"\x26\xF1\xB4\x89\xD6\x70\x1D\xD1\x85\xC8\x41\x3A\x97\x7B\x3C\xBB\xAF\x64\xD1\xC5\x93\xD2\x66\x27\xDF\xFB\x10\x1A\x87\xFF\x77\xDA"

#define p_RAW_2		"\x45\x31\xAC\xD1\xFE\x00\x23\xC7\x55\x0D\x26\x7B\x6B\x2F\xEE\x80\x92\x2B\x14\xB2\xFF\xB9\x0F\x04\xD4\xEB\x7C\x09\xB5\xD2\xD1\x5D\xF1\xD8\x52\x74\x1A\xF4\x70\x4A\x04\x58\x04\x7E\x80\xE4\x54\x6D\x35\xB8\x33\x6F\xAC\x22\x4D\xD8\x16\x64\xBB\xF5\x28\xBE\x63\x73"
#define a_RAW_2		"\x07"
#define b_RAW_2		"\x1C\xFF\x08\x06\xA3\x11\x16\xDA\x29\xD8\xCF\xA5\x4E\x57\xEB\x74\x8B\xC5\xF3\x77\xE4\x94\x00\xFD\xD7\x88\xB6\x49\xEC\xA1\xAC\x43\x61\x83\x40\x13\xB2\xAD\x73\x22\x48\x0A\x89\xCA\x58\xE0\xCF\x74\xBC\x9E\x54\x0C\x2A\xDD\x68\x97\xFA\xD0\xA3\x08\x4F\x30\x2A\xDC"
#define q_RAW_2		"\x45\x31\xAC\xD1\xFE\x00\x23\xC7\x55\x0D\x26\x7B\x6B\x2F\xEE\x80\x92\x2B\x14\xB2\xFF\xB9\x0F\x04\xD4\xEB\x7C\x09\xB5\xD2\xD1\x5D\xA8\x2F\x2D\x7E\xCB\x1D\xBA\xC7\x19\x90\x5C\x5E\xEC\xC4\x23\xF1\xD8\x6E\x25\xED\xBE\x23\xC5\x95\xD6\x44\xAA\xF1\x87\xE6\xE6\xDF"
#define GX_RAW_2	"\x24\xD1\x9C\xC6\x45\x72\xEE\x30\xF3\x96\xBF\x6E\xBB\xFD\x7A\x6C\x52\x13\xB3\xB3\xD7\x05\x7C\xC8\x25\xF9\x10\x93\xA6\x8C\xD7\x62\xFD\x60\x61\x12\x62\xCD\x83\x8D\xC6\xB6\x0A\xA7\xEE\xE8\x04\xE2\x8B\xC8\x49\x97\x7F\xAC\x33\xB4\xB5\x30\xF1\xB1\x20\x24\x8A\x9A"
#define GY_RAW_2	"\x2B\xB3\x12\xA4\x3B\xD2\xCE\x6E\x0D\x02\x06\x13\xC8\x57\xAC\xDD\xCF\xBF\x06\x1E\x91\xE5\xF2\xC3\xF3\x24\x47\xC2\x59\xF3\x9B\x2C\x83\xAB\x15\x6D\x77\xF1\x49\x6B\xF7\xEB\x33\x51\xE1\xEE\x4E\x43\xDC\x1A\x18\xB9\x1B\x24\x64\x0B\x6D\xBB\x92\xCB\x1A\xDD\x37\x1E"
#define k_RAW_2		"\x03\x59\xE7\xF4\xB1\x41\x0F\xEA\xCC\x57\x04\x56\xC6\x80\x14\x96\x94\x63\x12\x12\x0B\x39\xD0\x19\xD4\x55\x98\x6E\x36\x4F\x36\x58\x86\x74\x8E\xD7\xA4\x4B\x3E\x79\x44\x34\x00\x60\x11\x84\x22\x86\x21\x22\x73\xA6\xD1\x4C\xF7\x0E\xA3\xAF\x71\xBB\x1A\xE6\x79\xF1"
#define e_RAW_2		"\x37\x54\xF3\xCF\xAC\xC9\xE0\x61\x5C\x4F\x4A\x7C\x4D\x8D\xAB\x53\x1B\x09\xB6\xF9\xC1\x70\xC5\x33\xA7\x1D\x14\x70\x35\xB0\xC5\x91\x71\x84\xEE\x53\x65\x93\xF4\x41\x43\x39\x97\x6C\x64\x7C\x5D\x5A\x40\x7A\xDE\xDB\x1D\x56\x0C\x4F\xC6\x77\x7D\x29\x72\x07\x5B\x8C"
#define d_RAW_2		"\x0B\xA6\x04\x8A\xAD\xAE\x24\x1B\xA4\x09\x36\xD4\x77\x56\xD7\xC9\x30\x91\xA0\xE8\x51\x46\x69\x70\x0E\xE7\x50\x8E\x50\x8B\x10\x20\x72\xE8\x12\x3B\x22\x00\xA0\x56\x33\x22\xDA\xD2\x82\x7E\x27\x14\xA2\x63\x6B\x7B\xFD\x18\xAA\xDF\xC6\x29\x67\x82\x1F\xA1\x8D\xD4"
#define r_RAW_2		"\x2F\x86\xFA\x60\xA0\x81\x09\x1A\x23\xDD\x79\x5E\x1E\x3C\x68\x9E\xE5\x12\xA3\xC8\x2E\xE0\xDC\xC2\x64\x3C\x78\xEE\xA8\xFC\xAC\xD3\x54\x92\x55\x84\x86\xB2\x0F\x1C\x9E\xC1\x97\xC9\x06\x99\x85\x02\x60\xC9\x3B\xCB\xCD\x9C\x5C\x33\x17\xE1\x93\x44\xE1\x73\xAE\x36"
#define s_RAW_2     "\x10\x81\xB3\x94\x69\x6F\xFE\x8E\x65\x85\xE7\xA9\x36\x2D\x26\xB6\x32\x5F\x56\x77\x8A\xAD\xBC\x08\x1C\x0B\xFB\xE9\x33\xD5\x2F\xF5\x82\x3C\xE2\x88\xE8\xC4\xF3\x62\x52\x60\x80\xDF\x7F\x70\xCE\x40\x6A\x6E\xEB\x1F\x56\x91\x9C\xB9\x2A\x98\x53\xBD\xE7\x3E\x5B\x4A"
#define QX_RAW_2	"\x11\x5D\xC5\xBC\x96\x76\x0C\x7B\x48\x59\x8D\x8A\xB9\xE7\x40\xD4\xC4\xA8\x5A\x65\xBE\x33\xC1\x81\x5B\x5C\x32\x0C\x85\x46\x21\xDD\x5A\x51\x58\x56\xD1\x33\x14\xAF\x69\xBC\x5B\x92\x4C\x8B\x4D\xDF\xF7\x5C\x45\x41\x5C\x1D\x9D\xD9\xDD\x33\x61\x2C\xD5\x30\xEF\xE1"
#define QY_RAW_2	"\x37\xC7\xC9\x0C\xD4\x0B\x0F\x56\x21\xDC\x3A\xC1\xB7\x51\xCF\xA0\xE2\x63\x4F\xA0\x50\x3B\x3D\x52\x63\x9F\x5D\x7F\xB7\x2A\xFD\x61\xEA\x19\x94\x41\xD9\x43\xFF\xE7\xF0\xC7\x0A\x27\x59\xA3\xCD\xB8\x4C\x11\x4E\x1F\x93\x39\xFD\xF2\x7F\x35\xEC\xA9\x36\x77\xBE\xEC"

struct Param {
	uint8_t *data;
	uint_t  size;
};

struct Params {
	struct Param p;
	struct Param a;
	struct Param b;
	struct Param q;
	struct Param gx;
	struct Param gy;
	struct Param k;
	struct Param e;
	struct Param d;
	struct Param r;
	struct Param s;
	struct Param qx;
	struct Param qy;
};

static struct Params test[2] = {
	{
		p_RAW_1,  sizeof(p_RAW_1)  - 1,
		a_RAW_1,  sizeof(a_RAW_1)  - 1,
		b_RAW_1,  sizeof(b_RAW_1)  - 1,
		q_RAW_1,  sizeof(q_RAW_1)  - 1,
		GX_RAW_1, sizeof(GX_RAW_1) - 1,
		GY_RAW_1, sizeof(GY_RAW_1) - 1,
		k_RAW_1,  sizeof(k_RAW_1)  - 1,
		e_RAW_1,  sizeof(e_RAW_1)  - 1,
		d_RAW_1,  sizeof(d_RAW_1)  - 1,
		r_RAW_1,  sizeof(r_RAW_1)  - 1,
		s_RAW_1,  sizeof(s_RAW_1)  - 1,
		QX_RAW_1, sizeof(QX_RAW_1) - 1,
		QY_RAW_1, sizeof(QY_RAW_1) - 1,
	},
	{
		p_RAW_2,  sizeof(p_RAW_2) - 1,
		a_RAW_2,  sizeof(a_RAW_2) - 1,
		b_RAW_2,  sizeof(b_RAW_2) - 1,
		q_RAW_2,  sizeof(q_RAW_2) - 1,
		GX_RAW_2, sizeof(GX_RAW_2) - 1,
		GY_RAW_2, sizeof(GY_RAW_2) - 1,
		k_RAW_2,  sizeof(k_RAW_2) - 1,
		e_RAW_2,  sizeof(e_RAW_2) - 1,
		d_RAW_2,  sizeof(d_RAW_2) - 1,
		r_RAW_2,  sizeof(r_RAW_2) - 1,
		s_RAW_2,  sizeof(s_RAW_2) - 1,
		QX_RAW_2, sizeof(QX_RAW_2) - 1,
		QY_RAW_2, sizeof(QY_RAW_2) - 1,
	}
};

__weak_func error_t ecrdsaTest(void)
{
	error_t error;
	EcDomainParameters params;
	Mpi e;
	Mpi k;
	Mpi r; // test value
	Mpi s; // test value
	Mpi d; // private key
	Mpi v;
	Mpi z1;
	Mpi z2;
	EcPoint Q; // public key
	EcPoint C;
	EcrdsaSignature signature;

	ecInitDomainParameters(&params);
	params.h = 1;
	params.mod = NULL;
	mpiInit(&e);
	mpiInit(&k);
	mpiInit(&r);
	mpiInit(&s);
	mpiInit(&d);
	mpiInit(&v);
	mpiInit(&z1);
	mpiInit(&z2);
	ecInit(&Q);
	ecInit(&C);
	ecrdsaInitSignature(&signature);

	for (int i = 0; i < 2; ++i) {

		mpiReadRaw(&params.p, test[i].p.data, test[i].p.size);
		mpiReadRaw(&params.a, test[i].a.data, test[i].a.size);
		mpiReadRaw(&params.b, test[i].b.data, test[i].b.size);
		mpiReadRaw(&params.q, test[i].q.data, test[i].q.size);
		mpiReadRaw(&params.g.x, test[i].gx.data, test[i].gx.size);
		mpiReadRaw(&params.g.y, test[i].gy.data, test[i].gy.size);
		mpiSetValue(&params.g.z, 1);
		mpiReadRaw(&k, test[i].k.data, test[i].k.size);
		mpiReadRaw(&e, test[i].e.data, test[i].e.size);
		mpiReadRaw(&d, test[i].d.data, test[i].d.size);

		mpiReadRaw(&r, test[i].r.data, test[i].r.size);
		mpiReadRaw(&s, test[i].s.data, test[i].s.size);

		mpiReadRaw(&Q.x, test[i].qx.data, test[i].qx.size);
		mpiReadRaw(&Q.y, test[i].qy.data, test[i].qy.size);
		mpiSetValue(&Q.z, 1);

		TRACE_INFO("\r\nTest %d:\r\n", i + 1);
		TRACE_INFO("************\r\n");
		TRACE_INFO(" In:\r\n");

		TRACE_INFO("  p:\r\n");
		TRACE_INFO_MPI("    ", &params.p);
		TRACE_INFO("  a:\r\n");
		TRACE_INFO_MPI("    ", &params.a);
		TRACE_INFO("  b:\r\n");
		TRACE_INFO_MPI("    ", &params.b);
		TRACE_INFO("  q:\r\n");
		TRACE_INFO_MPI("    ", &params.q);
		TRACE_INFO("  Gx:\r\n");
		TRACE_INFO_MPI("    ", &params.g.x);
		TRACE_INFO("  Gy:\r\n");
		TRACE_INFO_MPI("    ", &params.g.y);
		TRACE_INFO("  k:\r\n");
		TRACE_INFO_MPI("    ", &k);
		TRACE_INFO("  e:\r\n");
		TRACE_INFO_MPI("    ", &e);
		TRACE_INFO("  d:\r\n");
		TRACE_INFO_MPI("    ", &d);


		/* Sign test */
		// Steps 1-3: Predefined
		// Step 1: Compute hash (h) of the message (passed as input) */ 
		// Step 2: Compute the integer a, the binary representation of which is the vector h, and determine e = a (mod q)
		// Step 3: Define k such as 0 < k < q, 

		// Step 4: Compute the point of the elliptic curve C = kP and determine r = Xc (mod q), where – Xc is the coordinate of point C. If r = 0, then go back to step 3.
		EC_CHECK(ecrdsaGenerateSignatureStep4(&params, &k, &C, &signature));
		// Step 5: Compute the value of s ≡ (rd + ke)(mod q). If s = 0, then go back to step 3.
		EC_CHECK(ecrdsaGenerateSignatureStep5(&d, &e, &k, &params.q, &signature));

		TRACE_INFO(" Out:\r\n");
		// Dump ECRDSA signature
		TRACE_INFO("  r:\r\n");
		TRACE_INFO_MPI("    ", &signature.r);
		TRACE_INFO("  s:\r\n");
		TRACE_INFO_MPI("    ", &signature.s);

		TRACE_INFO("Test %d sign result: %s\r\n", i + 1, (!mpiComp(&r, &signature.r) || !mpiComp(&s, &signature.s)) ? "OK" : "ERROR");


		/* Verify test */
		MPI_CHECK(ecrdsaVerifySignatureFinal(&params, &Q, &e, &signature));
		TRACE_INFO("Test %d veryfy result: %s\r\n", i + 1, error == NO_ERROR ? "OK" : "ERROR");
	}
end:
	// Release multiple precision integers
	mpiFree(&e);
	mpiFree(&k);
	mpiFree(&r);
	mpiFree(&s);
	mpiFree(&d);
	mpiFree(&v);
	mpiFree(&z1);
	mpiFree(&z2);
	// Release EC point
	ecFree(&C);
	ecFree(&Q);

	// Release (R, S) integer pair
	mpiFree(&signature.r);
	mpiFree(&signature.s);

	//Release previously allocated resources
	ecFreeDomainParameters(&params);

	// Return status code
	return error;
}

#endif

#endif
