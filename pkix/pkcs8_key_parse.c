/**
 * @file pkcs8_key_parse.c
 * @brief PKCS #8 key parsing
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
#include "pkix/pkcs8_key_parse.h"
#include "pkix/x509_key_parse.h"
#include "ecc/ec_misc.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Parse PrivateKeyInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] privateKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParsePrivateKeyInfo(const uint8_t *data, size_t length,
   Pkcs8PrivateKeyInfo *privateKeyInfo)
{
   error_t error;
   size_t n;
   size_t oidLen;
   const uint8_t *oid;
   Asn1Tag tag;

   //Clear the PrivateKeyInfo structure
   osMemset(privateKeyInfo, 0, sizeof(Pkcs8PrivateKeyInfo));

   //The private key information is encapsulated within a sequence
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //The Version field identifies the version of OneAsymmetricKey
   error = asn1ReadInt32(data, length, &tag, &privateKeyInfo->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Check version
   if(privateKeyInfo->version != PKCS8_VERSION_1 &&
      privateKeyInfo->version != PKCS8_VERSION_2)
   {
      return ERROR_INVALID_VERSION;
   }

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PrivateKeyAlgorithm field
   error = pkcs8ParsePrivateKeyAlgo(data, length, &n, privateKeyInfo);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The PrivateKey is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Get the private key algorithm identifier
   oid = privateKeyInfo->oid.value;
   oidLen = privateKeyInfo->oid.length;

#if (RSA_SUPPORT == ENABLED)
   //RSA or RSA-PSS algorithm identifier?
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //Read RSAPrivateKey structure
      error = pkcs8ParseRsaPrivateKey(tag.value, tag.length,
         &privateKeyInfo->rsaPrivateKey);
   }
   else
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(OID_COMP(oid, oidLen, DSA_OID) == 0)
   {
      //Read DSAPrivateKey structure
      error = pkcs8ParseDsaPrivateKey(tag.value, tag.length, NULL,
         &privateKeyInfo->dsaPrivateKey, NULL);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   if(OID_COMP(oid, oidLen, EC_PUBLIC_KEY_OID) == 0)
   {
      //Read ECPrivateKey structure
      error = pkcs8ParseEcPrivateKey(tag.value, tag.length,
         &privateKeyInfo->ecParams, &privateKeyInfo->ecPrivateKey,
         &privateKeyInfo->ecPublicKey);
   }
   else
#endif
#if (ED25519_SUPPORT == ENABLED)
   //X25519 or Ed25519 algorithm identifier?
   if(OID_COMP(oid, oidLen, X25519_OID) == 0 ||
      OID_COMP(oid, oidLen, ED25519_OID) == 0)
   {
      //Read CurvePrivateKey structure
      error = pkcs8ParseEddsaPrivateKey(tag.value, tag.length,
         &privateKeyInfo->eddsaPrivateKey);
   }
   else
#endif
#if (ED448_SUPPORT == ENABLED)
   //X448 or Ed448 algorithm identifier?
   if(OID_COMP(oid, oidLen, X448_OID) == 0 ||
      OID_COMP(oid, oidLen, ED448_OID) == 0)
   {
      //Read CurvePrivateKey structure
      error = pkcs8ParseEddsaPrivateKey(tag.value, tag.length,
         &privateKeyInfo->eddsaPrivateKey);
   }
   else
#endif
   //Unknown algorithm identifier?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Check version
   if(privateKeyInfo->version == PKCS8_VERSION_2)
   {
      //The OneAsymmetricKey structure allows for the public key and additional
      //attributes about the key to be included as well (refer to RFC 8410,
      //section 7)
      while(length > 0)
      {
         //Read current attribute
         error = asn1ReadTag(data, length, &tag);
         //Failed to decode ASN.1 tag?
         if(error)
            return error;

         //Explicit tagging shall be used to encode each optional attribute
         if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
            return ERROR_INVALID_CLASS;

         //Check attribute type
         if(tag.objType == 1)
         {
#if (ED25519_SUPPORT == ENABLED)
            //X25519 or Ed25519 algorithm identifier?
            if(OID_COMP(oid, oidLen, X25519_OID) == 0 ||
               OID_COMP(oid, oidLen, ED25519_OID) == 0)
            {
               //The publicKey field contains the elliptic curve public key
               //associated with the private key in question
               error = pkcs8ParseEddsaPublicKey(tag.value, tag.length,
                  &privateKeyInfo->eddsaPublicKey);
               //Any error to report?
               if(error)
                  return error;
            }
            else
#endif
#if (ED448_SUPPORT == ENABLED)
            //X448 or Ed448 algorithm identifier?
            if(OID_COMP(oid, oidLen, X448_OID) == 0 ||
               OID_COMP(oid, oidLen, ED448_OID) == 0)
            {
               //The publicKey field contains the elliptic curve public key
               //associated with the private key in question
               error = pkcs8ParseEddsaPublicKey(tag.value, tag.length,
                  &privateKeyInfo->eddsaPublicKey);
               //Any error to report?
               if(error)
                  return error;
            }
            else
#endif
            //Unknown algorithm identifier?
            {
               //Just for sanity
            }
         }

         //Next attribute
         data += tag.totalLength;
         length -= tag.totalLength;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PrivateKeyAlgorithm structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] privateKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParsePrivateKeyAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs8PrivateKeyInfo *privateKeyInfo)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the PrivateKeyAlgorithm structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read the private key algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the private key algorithm identifier
   privateKeyInfo->oid.value = tag.value;
   privateKeyInfo->oid.length = tag.length;

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
      error = x509ParseDsaParameters(data, length, &privateKeyInfo->dsaParams);
   }
   else
#endif
#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   if(!asn1CheckOid(&tag, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      //Read ECParameters structure
      error = x509ParseEcParameters(data, length, &privateKeyInfo->ecParams);
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
 * @brief Parse RSAPrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] rsaPrivateKey Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParseRsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8RsaPrivateKey *rsaPrivateKey)
{
   error_t error;
   Asn1Tag tag;

   //Read RSAPrivateKey structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read Version field
   error = asn1ReadInt32(data, length, &tag, &rsaPrivateKey->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

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
   rsaPrivateKey->n.value = tag.value;
   rsaPrivateKey->n.length = tag.length;

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
   rsaPrivateKey->e.value = tag.value;
   rsaPrivateKey->e.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PrivateExponent field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the private exponent
   rsaPrivateKey->d.value = tag.value;
   rsaPrivateKey->d.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Prime1 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the first factor
   rsaPrivateKey->p.value = tag.value;
   rsaPrivateKey->p.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Prime2 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the second factor
   rsaPrivateKey->q.value = tag.value;
   rsaPrivateKey->q.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Exponent1 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the first exponent
   rsaPrivateKey->dp.value = tag.value;
   rsaPrivateKey->dp.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Exponent2 field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the second exponent
   rsaPrivateKey->dq.value = tag.value;
   rsaPrivateKey->dq.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read Coefficient field
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the coefficient
   rsaPrivateKey->qinv.value = tag.value;
   rsaPrivateKey->qinv.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse DSAPrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] dsaParams DSA domain parameters
 * @param[out] dsaPrivateKey DSA private key
 * @param[out] dsaPublicKey DSA public key
 * @return Error code
 **/

error_t pkcs8ParseDsaPrivateKey(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams, Pkcs8DsaPrivateKey *dsaPrivateKey,
   X509DsaPublicKey *dsaPublicKey)
{
   error_t error;
   int32_t version;
   Asn1Tag tag;

   //The DSA domain parameters can be optionally parsed
   if(dsaParams != NULL && dsaPublicKey != NULL)
   {
      //Read DSAPrivateKey structure
      error = asn1ReadSequence(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Point to the first field of the sequence
      data = tag.value;
      length = tag.length;

      //Read version
      error = asn1ReadInt32(data, length, &tag, &version);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the parameter p
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
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
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
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
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         return error;

      //Save the parameter g
      dsaParams->g.value = tag.value;
      dsaParams->g.length = tag.length;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;

      //Read the public value y
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Enforce encoding, class and type
      error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
         ASN1_TYPE_INTEGER);
      //Invalid tag?
      if(error)
         return error;

      //Save the public value y
      dsaPublicKey->y.value = tag.value;
      dsaPublicKey->y.length = tag.length;

      //Point to the next field
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Read the private value x
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INTEGER);
   //Invalid tag?
   if(error)
      return error;

   //Save the private value x
   dsaPrivateKey->x.value = tag.value;
   dsaPrivateKey->x.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ECPrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecParams EC domain parameters
 * @param[out] ecPrivateKey EC private key
 * @param[out] ecPublicKey EC public key
 * @return Error code
 **/

error_t pkcs8ParseEcPrivateKey(const uint8_t *data, size_t length,
   X509EcParameters *ecParams, Pkcs8EcPrivateKey *ecPrivateKey,
   X509EcPublicKey *ecPublicKey)
{
   error_t error;
   Asn1Tag tag;

   //Read ECPrivateKey structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Read Version field
   error = asn1ReadInt32(data, length, &tag, &ecPrivateKey->version);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Read PrivateKey field
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the EC private key
   ecPrivateKey->d.value = tag.value;
   ecPrivateKey->d.length = tag.length;

   //Point to the next field
   data += tag.totalLength;
   length -= tag.totalLength;

   //Loop through optional attributes
   while(length > 0)
   {
      //Read current attribute
      error = asn1ReadTag(data, length, &tag);
      //Failed to decode ASN.1 tag?
      if(error)
         return error;

      //Explicit tagging shall be used to encode each optional attribute
      if(tag.objClass != ASN1_CLASS_CONTEXT_SPECIFIC)
         return ERROR_INVALID_CLASS;

      //Check attribute type
      if(tag.objType == 0)
      {
         //The parameters field specifies the elliptic curve domain parameters
         //associated to the private key
         error = x509ParseEcParameters(tag.value, tag.length, ecParams);
         //Any error to report?
         if(error)
            return error;
      }
      else if(tag.objType == 1)
      {
         //The publicKey field contains the elliptic curve public key associated
         //with the private key in question
         error = pkcs8ParseEcPublicKey(tag.value, tag.length, ecPublicKey);
         //Any error to report?
         if(error)
            return error;
      }
      else
      {
         //Ignore unknown attribute
      }

      //Next attribute
      data += tag.totalLength;
      length -= tag.totalLength;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse publicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] ecPublicKey EC public key
 * @return Error code
 **/

error_t pkcs8ParseEcPublicKey(const uint8_t *data, size_t length,
   X509EcPublicKey *ecPublicKey)
{
   error_t error;
   Asn1Tag tag;

   //The public key is encapsulated within a bit string
   error = asn1ReadTag(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Enforce encoding, class and type
   error = asn1CheckTag(&tag, FALSE, ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_BIT_STRING);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(tag.length < 1 || tag.value[0] != 0)
      return ERROR_INVALID_SYNTAX;

   //Save the EC public key
   ecPublicKey->q.value = tag.value + 1;
   ecPublicKey->q.length = tag.length - 1;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse CurvePrivateKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] eddsaPrivateKey EdDSA private key
 * @return Error code
 **/

error_t pkcs8ParseEddsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8EddsaPrivateKey *eddsaPrivateKey)
{
   error_t error;
   Asn1Tag tag;

   //The CurvePrivateKey structure is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the EdDSA private key
   eddsaPrivateKey->d.value = tag.value;
   eddsaPrivateKey->d.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse publicKey structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] eddsaPublicKey EdDSA public key
 * @return Error code
 **/

error_t pkcs8ParseEddsaPublicKey(const uint8_t *data, size_t length,
   Pkcs8EddsaPublicKey *eddsaPublicKey)
{
   //The bit string shall contain an initial octet which encodes the number
   //of unused bits in the final subsequent octet
   if(length < 1 || data[0] != 0)
      return ERROR_INVALID_SYNTAX;

   //Save the EdDSA public key
   eddsaPublicKey->q.value = data + 1;
   eddsaPublicKey->q.length = length - 1;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EncryptedPrivateKeyInfo structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] encryptedPrivateKeyInfo Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParseEncryptedPrivateKeyInfo(const uint8_t *data, size_t length,
   Pkcs8EncryptedPrivateKeyInfo *encryptedPrivateKeyInfo)
{
   error_t error;
   size_t n;
   Asn1Tag tag;

   //Read EncryptedPrivateKeyInfo structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Point to the first field
   data = tag.value;
   length = tag.length;

   //Parse EncryptionAlgorithmIdentifier structure
   error = pkcs8ParseEncryptionAlgoId(data, length, &n,
      &encryptedPrivateKeyInfo->encryptionAlgo);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += n;
   length -= n;

   //The EncryptedData is encapsulated within an octet string
   error = asn1ReadOctetString(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //The EncryptedData is the result of encrypting the private-key information
   encryptedPrivateKeyInfo->encryptedData.value = tag.value;
   encryptedPrivateKeyInfo->encryptedData.length = tag.length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EncryptionAlgorithmIdentifier structure
 * @param[in] data Pointer to the ASN.1 structure to parse
 * @param[in] length Length of the ASN.1 structure
 * @param[out] totalLength Number of bytes that have been parsed
 * @param[out] encryptionAlgoId Information resulting from the parsing process
 * @return Error code
 **/

error_t pkcs8ParseEncryptionAlgoId(const uint8_t *data, size_t length,
   size_t *totalLength, X509AlgoId *encryptionAlgoId)
{
   error_t error;
   Asn1Tag tag;

   //Read the contents of the EncryptionAlgorithmIdentifier structure
   error = asn1ReadSequence(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the total length of the sequence
   *totalLength = tag.totalLength;

   //Point to the first field of the sequence
   data = tag.value;
   length = tag.length;

   //Read the encryption algorithm identifier
   error = asn1ReadOid(data, length, &tag);
   //Failed to decode ASN.1 tag?
   if(error)
      return error;

   //Save the encryption algorithm identifier
   encryptionAlgoId->oid.value = tag.value;
   encryptionAlgoId->oid.length = tag.length;

   //Point to the next field (if any)
   data += tag.totalLength;
   length -= tag.totalLength;

   //The contents of the optional parameters field will vary according to the
   //algorithm identified
   encryptionAlgoId->params.value = data;
   encryptionAlgoId->params.length = length;

   //Return status code
   return error;
}


/**
 * @brief Import an RSA private key
 * @param[out] privateKey RSA private key
 * @param[in] privateKeyInfo Private key information
 * @return Error code
 **/

error_t pkcs8ImportRsaPrivateKey(RsaPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo)
{
   error_t error;

#if (RSA_SUPPORT == ENABLED)
   const uint8_t *oid;
   size_t oidLen;

   //Get the private key algorithm identifier
   oid = privateKeyInfo->oid.value;
   oidLen = privateKeyInfo->oid.length;

   //RSA or RSA-PSS algorithm identifier?
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //Sanity check
      if(privateKeyInfo->rsaPrivateKey.n.value != NULL &&
         privateKeyInfo->rsaPrivateKey.e.value != NULL &&
         privateKeyInfo->rsaPrivateKey.d.value != NULL &&
         privateKeyInfo->rsaPrivateKey.p.value != NULL &&
         privateKeyInfo->rsaPrivateKey.q.value != NULL &&
         privateKeyInfo->rsaPrivateKey.dp.value != NULL &&
         privateKeyInfo->rsaPrivateKey.dq.value != NULL &&
         privateKeyInfo->rsaPrivateKey.qinv.value != NULL)
      {
         //Read modulus
         error = mpiImport(&privateKey->n,
            privateKeyInfo->rsaPrivateKey.n.value,
            privateKeyInfo->rsaPrivateKey.n.length, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read public exponent
            error = mpiImport(&privateKey->e,
               privateKeyInfo->rsaPrivateKey.e.value,
               privateKeyInfo->rsaPrivateKey.e.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read private exponent
            error = mpiImport(&privateKey->d,
               privateKeyInfo->rsaPrivateKey.d.value,
               privateKeyInfo->rsaPrivateKey.d.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read first factor
            error = mpiImport(&privateKey->p,
               privateKeyInfo->rsaPrivateKey.p.value,
               privateKeyInfo->rsaPrivateKey.p.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read second factor
            error = mpiImport(&privateKey->q,
               privateKeyInfo->rsaPrivateKey.q.value,
               privateKeyInfo->rsaPrivateKey.q.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read first exponent
            error = mpiImport(&privateKey->dp,
               privateKeyInfo->rsaPrivateKey.dp.value,
               privateKeyInfo->rsaPrivateKey.dp.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read second exponent
            error = mpiImport(&privateKey->dq,
               privateKeyInfo->rsaPrivateKey.dq.value,
               privateKeyInfo->rsaPrivateKey.dq.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read coefficient
            error = mpiImport(&privateKey->qinv,
               privateKeyInfo->rsaPrivateKey.qinv.value,
               privateKeyInfo->rsaPrivateKey.qinv.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Dump RSA private key
            TRACE_DEBUG("RSA private key:\r\n");
            TRACE_DEBUG("  Modulus:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->n);
            TRACE_DEBUG("  Public exponent:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->e);
            TRACE_DEBUG("  Private exponent:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->d);
            TRACE_DEBUG("  Prime 1:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->p);
            TRACE_DEBUG("  Prime 2:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->q);
            TRACE_DEBUG("  Prime exponent 1:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->dp);
            TRACE_DEBUG("  Prime exponent 2:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->dq);
            TRACE_DEBUG("  Coefficient:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->qinv);
         }
      }
      else
      {
         //The private key is not valid
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
 * @brief Import a DSA private key
 * @param[out] privateKey DSA private key
 * @param[in] privateKeyInfo Private key information
 * @return Error code
 **/

error_t pkcs8ImportDsaPrivateKey(DsaPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo)
{
   error_t error;

#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   if(OID_COMP(privateKeyInfo->oid.value, privateKeyInfo->oid.length,
      DSA_OID) == 0)
   {
      //Sanity check
      if(privateKeyInfo->dsaParams.p.value != NULL &&
         privateKeyInfo->dsaParams.q.value != NULL &&
         privateKeyInfo->dsaParams.g.value != NULL &&
         privateKeyInfo->dsaPrivateKey.x.value != NULL)
      {
         //Read parameter p
         error = mpiImport(&privateKey->params.p,
            privateKeyInfo->dsaParams.p.value,
            privateKeyInfo->dsaParams.p.length, MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Read parameter q
            error = mpiImport(&privateKey->params.q,
               privateKeyInfo->dsaParams.q.value,
               privateKeyInfo->dsaParams.q.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read parameter g
            error = mpiImport(&privateKey->params.g,
               privateKeyInfo->dsaParams.g.value,
               privateKeyInfo->dsaParams.g.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Read private value
            error = mpiImport(&privateKey->x,
               privateKeyInfo->dsaPrivateKey.x.value,
               privateKeyInfo->dsaPrivateKey.x.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //The public key is optional
            if(privateKeyInfo->dsaPublicKey.y.value != NULL)
            {
               //Read public value
               error = mpiImport(&privateKey->y,
                  privateKeyInfo->dsaPublicKey.y.value,
                  privateKeyInfo->dsaPublicKey.y.length, MPI_FORMAT_BIG_ENDIAN);
            }
            else
            {
               //The public key is not present
               mpiFree(&privateKey->y);
               mpiInit(&privateKey->y);
            }
         }

         //Check status code
         if(!error)
         {
            //Dump DSA private key
            TRACE_DEBUG("DSA private key:\r\n");
            TRACE_DEBUG("  Parameter p:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->params.p);
            TRACE_DEBUG("  Parameter q:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->params.q);
            TRACE_DEBUG("  Parameter g:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->params.g);
            TRACE_DEBUG("  Private value x:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->x);
            TRACE_DEBUG("  Public value y:\r\n");
            TRACE_DEBUG_MPI("    ", &privateKey->y);
         }
      }
      else
      {
         //The private key is not valid
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
 * @brief Import an EC private key
 * @param[out] privateKey EC private key
 * @param[in] privateKeyInfo Private key information
 * @return Error code
 **/

error_t pkcs8ImportEcPrivateKey(EcPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo)
{
   error_t error;

#if (EC_SUPPORT == ENABLED)
   //EC public key algorithm identifier?
   if(OID_COMP(privateKeyInfo->oid.value, privateKeyInfo->oid.length,
      EC_PUBLIC_KEY_OID) == 0)
   {
      //Sanity check
      if(privateKeyInfo->ecParams.namedCurve.value != NULL &&
         privateKeyInfo->ecPrivateKey.d.value != NULL)
      {
         const EcCurve *curve;

         //Get the elliptic curve that matches the OID
         curve = ecGetCurve(privateKeyInfo->ecParams.namedCurve.value,
            privateKeyInfo->ecParams.namedCurve.length);

         //Make sure the specified elliptic curve is supported
         if(curve != NULL)
         {
            //Read the EC private key
            error = ecImportPrivateKey(privateKey, curve,
               privateKeyInfo->ecPrivateKey.d.value,
               privateKeyInfo->ecPrivateKey.d.length);

            //Check status code
            if(!error)
            {
               //The public key is optional
               if(privateKeyInfo->ecPublicKey.q.value != NULL)
               {
                  //Read the EC public key
                  error = ecImportPublicKey(&privateKey->q, curve,
                     privateKeyInfo->ecPublicKey.q.value,
                     privateKeyInfo->ecPublicKey.q.length,
                     EC_PUBLIC_KEY_FORMAT_X963);
               }
               else
               {
                  //The EC public key is not present
                  ecInitPublicKey(&privateKey->q);
               }
            }
         }
         else
         {
            //Invalid elliptic curve
            error = ERROR_WRONG_IDENTIFIER;
         }

         //Check status code
         if(!error)
         {
            //Dump EC private key
            TRACE_DEBUG("EC private key:\r\n");
            TRACE_DEBUG_EC_SCALAR("  ", privateKey->d, (curve->orderSize + 31) / 32);

            //Valid public key?
            if(privateKey->q.curve != NULL)
            {
               //Dump EC public key
               TRACE_DEBUG("EC public key X:\r\n");
               TRACE_DEBUG_EC_SCALAR("  ", privateKey->q.q.x, (curve->fieldSize + 31) / 32);
               TRACE_DEBUG("EC public key Y:\r\n");
               TRACE_DEBUG_EC_SCALAR("  ", privateKey->q.q.y, (curve->fieldSize + 31) / 32);
            }
         }
      }
      else
      {
         //The private key is not valid
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
 * @brief Import an EdDSA private key
 * @param[out] privateKey EdDSA private key
 * @param[in] privateKeyInfo Private key information
 * @return Error code
 **/

error_t pkcs8ImportEddsaPrivateKey(EddsaPrivateKey *privateKey,
   const Pkcs8PrivateKeyInfo *privateKeyInfo)
{
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   error_t error;
   const EcCurve *curve;

   //Get the elliptic curve that matches the OID
   curve = ecGetCurve(privateKeyInfo->oid.value, privateKeyInfo->oid.length);

   //Edwards elliptic curve?
   if(curve != NULL && curve->type == EC_CURVE_TYPE_EDWARDS)
   {
      //Read the EdDSA private key
      error = eddsaImportPrivateKey(privateKey, curve,
         privateKeyInfo->eddsaPrivateKey.d.value,
         privateKeyInfo->eddsaPrivateKey.d.length);

      //Check status code
      if(!error)
      {
         //The public key is optional
         if(privateKeyInfo->eddsaPublicKey.q.value != NULL)
         {
            //Read the EdDSA public key
            error = eddsaImportPublicKey(&privateKey->q, curve,
               privateKeyInfo->eddsaPublicKey.q.value,
               privateKeyInfo->eddsaPublicKey.q.length);
         }
         else
         {
            //The EdDSA public key is not present
            eddsaInitPublicKey(&privateKey->q);
         }
      }
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Check status code
   if(!error)
   {
      //Dump EdDSA private key
      TRACE_DEBUG("EdDSA private key:\r\n");
      TRACE_DEBUG_ARRAY("  ", privateKey->d, privateKeyInfo->eddsaPrivateKey.d.length);

      //Valid public key?
      if(privateKey->q.curve != NULL)
      {
         //Dump EdDSA public key
         TRACE_DEBUG("EdDSA public key:\r\n");
         TRACE_DEBUG_ARRAY("  ", privateKey->q.q, privateKeyInfo->eddsaPublicKey.q.length);
      }
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
