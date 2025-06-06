/**
 * @file x509_key_parse.c
 * @brief Parsing of ASN.1 encoded keys
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
#include "pkix/x509_key_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "ecc/eddsa.h"
#include "ecc/ec_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED || PEM_SUPPORT == ENABLED)


/**
 * @brief Parse SubjectPublicKeyInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] publicKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseSubjectPublicKeyInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *publicKeyInfo)
{
   error_t error;
   size_t n;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("    Parsing SubjectPublicKeyInfo...\r\n");

   //Clear the SubjectPublicKeyInfo structure
   osMemset(publicKeyInfo, 0, sizeof(X509SubjectPublicKeyInfo));

   //The public key information is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Raw contents of the ASN.1 sequence
   publicKeyInfo->raw.value = data;
   publicKeyInfo->raw.length = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read AlgorithmIdentifier field
   error = x509ParseAlgoId(data, length, &n, publicKeyInfo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The SubjectPublicKey is encapsulated within a bit string
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_BIT_STRING);
   //Invalid tag?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(tag.length < 1 || tag.value[0] != 0x00)
      return ERROR_FAILURE;

   //Point to the public key
   data = tag.value + 1;
   length = tag.length - 1;

   //Raw contents of the SubjectPublicKey (excluding the tag, length, and
   //number of unused bits)
   publicKeyInfo->rawSubjectPublicKey.value = data;
   publicKeyInfo->rawSubjectPublicKey.length = length;

   //Get the public key algorithm identifier
   oid = publicKeyInfo->oid.value;
   oidLen = publicKeyInfo->oid.length;

#if (RSA_SUPPORT == ENABLED)
   //RSA or RSA-PSS algorithm identifier?
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //Read RSAPublicKey structure
      error = x509ParseRsaPublicKey(data, length, &publicKeyInfo->rsaPublicKey);
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(OID_COMP(oid, oidLen, DSA_OID) == 0)
   {
      //Read DSAPublicKey structure
      error = x509ParseDsaPublicKey(data, length, &publicKeyInfo->dsaPublicKey);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   if(OID_COMP(oid, oidLen, EC_PUBLIC_KEY_OID) == 0)
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(data, length, &publicKeyInfo->ecPublicKey);
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(OID_COMP(oid, oidLen, X25519_OID) == 0 ||
      OID_COMP(oid, oidLen, ED25519_OID) == 0)
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(data, length, &publicKeyInfo->ecPublicKey);
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(OID_COMP(oid, oidLen, X448_OID) == 0 ||
      OID_COMP(oid, oidLen, ED448_OID) == 0)
   {
      //Read ECPublicKey structure
      error = x509ParseEcPublicKey(data, length, &publicKeyInfo->ecPublicKey);
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse AlgorithmIdentifier structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] publicKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseAlgoId(const uint8_t *data, size_t length,
   size_t *totalLength, X509SubjectPublicKeyInfo *publicKeyInfo)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing AlgorithmIdentifier...\r\n");

   //Read AlgorithmIdentifier field
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the field
   *totalLength = tag.totalLength;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read algorithm identifier (OID)
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the algorithm identifier
   publicKeyInfo->oid.value = tag.value;
   publicKeyInfo->oid.length = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

#if (RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   if(!asn1CheckOid(&tag, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      //The parameters field must have ASN.1 type NULL for this algorithm
      //identifier (refer to RFC 3279, section 2.3.1)
      error = NO_ERROR;
   }
   //RSA-PSS algorithm identifier?
   else if(!asn1CheckOid(&tag, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      //The parameters may be either absent or present when used as subject
      //public key information (refer to RFC 4055, section 3.1)
      error = NO_ERROR;
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(!asn1CheckOid(&tag, DSA_OID, sizeof(DSA_OID)))
   {
      //Read DsaParameters structure
      error = x509ParseDsaParameters(data, length, &publicKeyInfo->dsaParams);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECParameters structure
      error = x509ParseEcParameters(data, length, &publicKeyInfo->ecParams);
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(!asn1CheckOid(&tag, X25519_OID, sizeof(X25519_OID)) ||
      !asn1CheckOid(&tag, ED25519_OID, sizeof(ED25519_OID)))
   {
      //For all of the OIDs, the parameters must be absent (refer to RFC 8410,
      //section 3)
      error = NO_ERROR;
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(!asn1CheckOid(&tag, X448_OID, sizeof(X448_OID)) ||
      !asn1CheckOid(&tag, ED448_OID, sizeof(ED448_OID)))
   {
      //For all of the OIDs, the parameters must be absent (refer to RFC 8410,
      //section 3)
      error = NO_ERROR;
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse RSAPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseRsaPublicKey(const uint8_t *data, size_t length,
   X509RsaPublicKey *rsaPublicKey)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing RSAPublicKey...\r\n");

   //Read RSAPublicKey structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read Modulus field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the modulus
   rsaPublicKey->n.value = tag.value;
   rsaPublicKey->n.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PublicExponent field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the public exponent
   rsaPublicKey->e.value = tag.value;
   rsaPublicKey->e.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DSAPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaPublicKey(const uint8_t *data, size_t length,
   X509DsaPublicKey *dsaPublicKey)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("      Parsing DSAPublicKey...\r\n");

   //Read DSAPublicKey structure
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the DSA public value
   dsaPublicKey->y.value = tag.value;
   dsaPublicKey->y.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DSA domain parameters
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseDsaParameters(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing DSAParameters...\r\n");

   //Read DSAParameters structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read the parameter p
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter p
   dsaParams->p.value = tag.value;
   dsaParams->p.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the parameter q
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter q
   dsaParams->q.value = tag.value;
   dsaParams->q.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read the parameter g
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the parameter g
   dsaParams->g.value = tag.value;
   dsaParams->g.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ECPublicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecPublicKey Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcPublicKey(const uint8_t *data, size_t length,
   X509EcPublicKey *ecPublicKey)
{
   //Debug message
   TRACE_DEBUG("      Parsing ECPublicKey...\r\n");

   //Make sure the EC public key is valid
   if(length == 0)
      return ERROR_BAD_CERTIFICATE;

   //Save the EC public key
   ecPublicKey->q.value = data;
   ecPublicKey->q.length = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ECParameters structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecParams Information resulting from the parsing process
 * @return Error code
 **/

error_t x509ParseEcParameters(const uint8_t *data, size_t length,
   X509EcParameters *ecParams)
{
   error_t error;
   Asn1Tag tag;

   //Debug message
   TRACE_DEBUG("        Parsing ECParameters...\r\n");

   //Read namedCurve field
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The namedCurve field identifies all the required values for a particular
   //set of elliptic curve domain parameters to be represented by an object
   //identifier
   ecParams->namedCurve.value = tag.value;
   ecParams->namedCurve.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import an RSA public key
 * @param[out] publicKey RSA public key
 * @param[in] publicKeyInfo Public key information
 * @return Error code
 **/

error_t x509ImportRsaPublicKey(RsaPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo)
{
   error_t error;

#if (RSA_SUPPORT == ENABLED)
   const uint8_t *oid;
   size_t oidLen;

   //Get the public key algorithm identifier
   oid = publicKeyInfo->oid.value;
   oidLen = publicKeyInfo->oid.length;

   //RSA algorithm identifier?
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //Sanity check
      if(publicKeyInfo->rsaPublicKey.n.value != NULL &&
         publicKeyInfo->rsaPublicKey.e.value != NULL)
      {
         //Read modulus
         error = mpiImport(&publicKey->n, publicKeyInfo->rsaPublicKey.n.value,
            publicKeyInfo->rsaPublicKey.n.length, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read public exponent
            error = mpiImport(&publicKey->e, publicKeyInfo->rsaPublicKey.e.value,
               publicKeyInfo->rsaPublicKey.e.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("RSA public key:\r\n");
            TRACE_DEBUG("  Modulus:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->n);
            TRACE_DEBUG("  Public exponent:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->e);
         }
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
   //Invalid algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Import a DSA public key
 * @param[out] publicKey DSA public key
 * @param[in] publicKeyInfo Public key information
 * @return Error code
 **/

error_t x509ImportDsaPublicKey(DsaPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo)
{
   error_t error;

#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(OID_COMP(publicKeyInfo->oid.value, publicKeyInfo->oid.length,
      DSA_OID) == 0)
   {
      //Sanity check
      if(publicKeyInfo->dsaParams.p.value != NULL &&
         publicKeyInfo->dsaParams.q.value != NULL &&
         publicKeyInfo->dsaParams.g.value != NULL &&
         publicKeyInfo->dsaPublicKey.y.value != NULL)
      {
         //Read parameter p
         error = mpiImport(&publicKey->params.p,
            publicKeyInfo->dsaParams.p.value,
            publicKeyInfo->dsaParams.p.length, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read parameter q
            error = mpiImport(&publicKey->params.q,
               publicKeyInfo->dsaParams.q.value,
               publicKeyInfo->dsaParams.q.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read parameter g
            error = mpiImport(&publicKey->params.g,
               publicKeyInfo->dsaParams.g.value,
               publicKeyInfo->dsaParams.g.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read public value
            error = mpiImport(&publicKey->y,
               publicKeyInfo->dsaPublicKey.y.value,
               publicKeyInfo->dsaPublicKey.y.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("DSA public key:\r\n");
            TRACE_DEBUG("  Parameter p:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->params.p);
            TRACE_DEBUG("  Parameter q:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->params.q);
            TRACE_DEBUG("  Parameter g:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->params.g);
            TRACE_DEBUG("  Public value y:\r\n");
            TRACE_DEBUG_MPI("    ", &publicKey->y);
         }
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
   //Invalid algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Import an EC public key
 * @param[out] publicKey EC public key
 * @param[in] publicKeyInfo Public key information
 * @return Error code
 **/

error_t x509ImportEcPublicKey(EcPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo)
{
   error_t error;

#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   if(OID_COMP(publicKeyInfo->oid.value, publicKeyInfo->oid.length,
      EC_PUBLIC_KEY_OID) == 0)
   {
      //Sanity check
      if(publicKeyInfo->ecParams.namedCurve.value != NULL &&
         publicKeyInfo->ecPublicKey.q.value != NULL)
      {
         const EcCurve *curve;

         //Get the elliptic curve that matches the OID
         curve = ecGetCurve(publicKeyInfo->ecParams.namedCurve.value,
            publicKeyInfo->ecParams.namedCurve.length);

         //Make sure the specified elliptic curve is supported
         if(curve != NULL)
         {
            //Read the EC public key
            error = ecImportPublicKey(publicKey, curve,
               publicKeyInfo->ecPublicKey.q.value,
               publicKeyInfo->ecPublicKey.q.length, EC_PUBLIC_KEY_FORMAT_X963);
         }
         else
         {
            //Invalid elliptic curve
            error = ERROR_WRONG_IDENTIFIER;
         }

         //Check status code
         if(!error)
         {
            //Dump EC public key
            TRACE_DEBUG("EC public key X:\r\n");
            TRACE_DEBUG_EC_SCALAR("  ", publicKey->q.x, (curve->fieldSize + 31) / 32);
            TRACE_DEBUG("EC public key Y:\r\n");
            TRACE_DEBUG_EC_SCALAR("  ", publicKey->q.y, (curve->fieldSize + 31) / 32);
         }
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
#endif
   //Invalid algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Return status code
   return error;
}


/**
 * @brief Import an EdDSA public key
 * @param[out] publicKey EdDSA public key
 * @param[in] publicKeyInfo Public key information
 * @return Error code
 **/

error_t x509ImportEddsaPublicKey(EddsaPublicKey *publicKey,
   const X509SubjectPublicKeyInfo *publicKeyInfo)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   const EcCurve *curve;

   //Get the elliptic curve that matches the OID
   curve = ecGetCurve(publicKeyInfo->oid.value, publicKeyInfo->oid.length);

   //Edwards elliptic curve?
   if(curve != NULL && curve->type == EC_CURVE_TYPE_EDWARDS)
   {
      //Read the EdDSA public key
      error = eddsaImportPublicKey(publicKey, curve,
         publicKeyInfo->ecPublicKey.q.value,
         publicKeyInfo->ecPublicKey.q.length);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Check status code
   if(!error)
   {
      //Dump EdDSA public key
      TRACE_DEBUG("EdDSA public key:\r\n");
      TRACE_DEBUG_ARRAY("  ", publicKey->q, publicKeyInfo->ecPublicKey.q.length);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
