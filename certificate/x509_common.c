/**
 * @file x509_common.c
 * @brief X.509 common definitions
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.8.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "certificate/x509_common.h"
#include "encoding/oid.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)

//Common Name OID (2.5.4.3)
const uint8_t X509_COMMON_NAME_OID[3] = {0x55, 0x04, 0x03};
//Surname OID (2.5.4.4)
const uint8_t X509_SURNAME_OID[3] = {0x55, 0x04, 0x04};
//Serial Number OID (2.5.4.5)
const uint8_t X509_SERIAL_NUMBER_OID[3] = {0x55, 0x04, 0x05};
//Country Name OID (2.5.4.6)
const uint8_t X509_COUNTRY_NAME_OID[3] = {0x55, 0x04, 0x06};
//Locality Name OID (2.5.4.7)
const uint8_t X509_LOCALITY_NAME_OID[3] = {0x55, 0x04, 0x07};
//State Or Province Name OID (2.5.4.8)
const uint8_t X509_STATE_OR_PROVINCE_NAME_OID[] = {0x55, 0x04, 0x08};
//Organization Name OID (2.5.4.10)
const uint8_t X509_ORGANIZATION_NAME_OID[3] = {0x55, 0x04, 0x0A};
//Organizational Unit Name OID (2.5.4.11)
const uint8_t X509_ORGANIZATIONAL_UNIT_NAME_OID[3] = {0x55, 0x04, 0x0B};
//Title OID (2.5.4.12)
const uint8_t X509_TITLE_OID[3] = {0x55, 0x04, 0x0C};
//Name OID (2.5.4.41)
const uint8_t X509_NAME_OID[3] = {0x55, 0x04, 0x29};
//Given Name OID (2.5.4.42)
const uint8_t X509_GIVEN_NAME_OID[3] = {0x55, 0x04, 0x2A};
//Initials OID (2.5.4.43)
const uint8_t X509_INITIALS_OID[3] = {0x55, 0x04, 0x2B};
//Generation Qualifier OID (2.5.4.44)
const uint8_t X509_GENERATION_QUALIFIER_OID[3] = {0x55, 0x04, 0x2C};
//DN Qualifier OID (2.5.4.46)
const uint8_t X509_DN_QUALIFIER_OID[3] = {0x55, 0x04, 0x2E};
//Pseudonym OID (2.5.4.65)
const uint8_t X509_PSEUDONYM_OID[3] = {0x55, 0x04, 0x41};

//Subject Directory Attributes OID (2.5.29.9)
const uint8_t X509_SUBJECT_DIRECTORY_ATTR_OID[3] = {0x55, 0x1D, 0x09};
//Subject Key Identifier OID (2.5.29.14)
const uint8_t X509_SUBJECT_KEY_ID_OID[3] = {0x55, 0x1D, 0x0E};
//Key Usage OID (2.5.29.15)
const uint8_t X509_KEY_USAGE_OID[3] = {0x55, 0x1D, 0x0F};
//Subject Alternative Name OID (2.5.29.17)
const uint8_t X509_SUBJECT_ALT_NAME_OID[3] = {0x55, 0x1D, 0x11};
//Issuer Alternative Name OID (2.5.29.18)
const uint8_t X509_ISSUER_ALT_NAME_OID[3] = {0x55, 0x1D, 0x12};
//Basic Constraints OID (2.5.29.19)
const uint8_t X509_BASIC_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x13};
//Name Constraints OID (2.5.29.30)
const uint8_t X509_NAME_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x1E};
//CRL Distribution Points OID (2.5.29.31)
const uint8_t X509_CRL_DISTR_POINTS_OID[3] = {0x55, 0x1D, 0x1F};
//Certificate Policies OID (2.5.29.32)
const uint8_t X509_CERTIFICATE_POLICIES_OID[3] = {0x55, 0x1D, 0x20};
//Policy Mappings OID (2.5.29.33)
const uint8_t X509_POLICY_MAPPINGS_OID[3] = {0x55, 0x1D, 0x21};
//Authority Key Identifier OID (2.5.29.35)
const uint8_t X509_AUTHORITY_KEY_ID_OID[3] = {0x55, 0x1D, 0x23};
//Policy Constraints OID (2.5.29.36)
const uint8_t X509_POLICY_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x24};
//Extended Key Usage OID (2.5.29.37)
const uint8_t X509_EXTENDED_KEY_USAGE_OID[3] = {0x55, 0x1D, 0x25};
//Freshest CRL OID (2.5.29.46)
const uint8_t X509_FRESHEST_CRL_OID[3] = {0x55, 0x1D, 0x2E};
//Inhibit Any-Policy OID (2.5.29.54)
const uint8_t X509_INHIBIT_ANY_POLICY_OID[3] = {0x55, 0x1D, 0x36};

//Netscape Certificate Type OID (2.16.840.1.113730.1.1)
const uint8_t X509_NS_CERT_TYPE_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01};

//Any Extended Key Usage OID (2.5.29.37.0)
const uint8_t X509_ANY_EXT_KEY_USAGE_OID[4] = {0x55, 0x1D, 0x25, 0x00};
//Key Purpose Server Auth OID (1.3.6.1.5.5.7.3.1)
const uint8_t X509_KP_SERVER_AUTH_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
//Key Purpose Client Auth OID (1.3.6.1.5.5.7.3.2)
const uint8_t X509_KP_CLIENT_AUTH_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};
//Key Purpose Code Signing OID (1.3.6.1.5.5.7.3.3)
const uint8_t X509_KP_CODE_SIGNING_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03};
//Key Purpose Email Protection OID (1.3.6.1.5.5.7.3.4)
const uint8_t X509_KP_EMAIL_PROTECTION_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04};
//Key Purpose Time Stamping OID (1.3.6.1.5.5.7.3.8)
const uint8_t X509_KP_TIME_STAMPING_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08};
//Key Purpose OCSP Signing OID (1.3.6.1.5.5.7.3.9)
const uint8_t X509_KP_OCSP_SIGNING_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09};


/**
 * @brief Convert string to integer
 * @param[in] data String containing the representation of an integral number
 * @param[in] length Length of the string
 * @param[out] value On success, the function returns the converted integral number
 * @return Error code
 **/

error_t x509ReadInt(const uint8_t *data, size_t length, uint_t *value)
{
   //Initialize integer value
   *value = 0;

   //Parse the string
   while(length > 0)
   {
      //Check whether the character is decimal digit
      if(!cryptoIsdigit(*data))
         return ERROR_FAILURE;

      //Convert the string to integer
      *value = *value * 10 + (*data - '0');

      //Next character
      data++;
      length--;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Read a RSA public key
 * @param[in] certInfo X.509 certificate
 * @param[out] key RSA public key
 * @return Error code
 **/

error_t x509ReadRsaPublicKey(const X509CertificateInfo *certInfo,
   RsaPublicKey *key)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;

   //The certificate shall contain a valid RSA public key
   if(!certInfo->subjectPublicKeyInfo.rsaPublicKey.n ||
      !certInfo->subjectPublicKeyInfo.rsaPublicKey.e)
   {
      //Report an error
      return ERROR_INVALID_KEY;
   }

   //Convert the modulus to a big number
   error = mpiReadRaw(&key->n, certInfo->subjectPublicKeyInfo.rsaPublicKey.n,
      certInfo->subjectPublicKeyInfo.rsaPublicKey.nLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the public exponent to a big number
   error = mpiReadRaw(&key->e, certInfo->subjectPublicKeyInfo.rsaPublicKey.e,
      certInfo->subjectPublicKeyInfo.rsaPublicKey.eLen);
   //Convertion failed?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("RSA public key:\r\n");
   TRACE_DEBUG("  Modulus:\r\n");
   TRACE_DEBUG_MPI("    ", &key->n);
   TRACE_DEBUG("  Public exponent:\r\n");
   TRACE_DEBUG_MPI("    ", &key->e);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Read a DSA public key
 * @param[in] certInfo X.509 certificate
 * @param[out] key DSA public key
 * @return Error code
 **/

error_t x509ReadDsaPublicKey(const X509CertificateInfo *certInfo,
   DsaPublicKey *key)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;

   //The certificate shall contain a valid DSA public key
   if(!certInfo->subjectPublicKeyInfo.dsaParams.p ||
      !certInfo->subjectPublicKeyInfo.dsaParams.q ||
      !certInfo->subjectPublicKeyInfo.dsaParams.g ||
      !certInfo->subjectPublicKeyInfo.dsaPublicKey.y)
   {
      //Report an error
      return ERROR_INVALID_KEY;
   }

   //Convert the parameter p to a big number
   error = mpiReadRaw(&key->p, certInfo->subjectPublicKeyInfo.dsaParams.p,
      certInfo->subjectPublicKeyInfo.dsaParams.pLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the parameter q to a big number
   error = mpiReadRaw(&key->q, certInfo->subjectPublicKeyInfo.dsaParams.q,
      certInfo->subjectPublicKeyInfo.dsaParams.qLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the parameter g to a big number
   error = mpiReadRaw(&key->g, certInfo->subjectPublicKeyInfo.dsaParams.g,
      certInfo->subjectPublicKeyInfo.dsaParams.gLen);
   //Convertion failed?
   if(error)
      return error;

   //Convert the public value to a big number
   error = mpiReadRaw(&key->y, certInfo->subjectPublicKeyInfo.dsaPublicKey.y,
      certInfo->subjectPublicKeyInfo.dsaPublicKey.yLen);
   //Convertion failed?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("DSA public key:\r\n");
   TRACE_DEBUG("  Parameter p:\r\n");
   TRACE_DEBUG_MPI("    ", &key->p);
   TRACE_DEBUG("  Parameter q:\r\n");
   TRACE_DEBUG_MPI("    ", &key->q);
   TRACE_DEBUG("  Parameter g:\r\n");
   TRACE_DEBUG_MPI("    ", &key->g);
   TRACE_DEBUG("  Public value y:\r\n");
   TRACE_DEBUG_MPI("    ", &key->y);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Get the elliptic curve that matches the specified OID
 * @param[in] oid Object identifier
 * @param[in] length OID length
 * @return Elliptic curve domain parameters
 **/

const EcCurveInfo *x509GetCurveInfo(const uint8_t *oid, size_t length)
{
   const EcCurveInfo *curveInfo;

   //Default elliptic curve domain parameters
   curveInfo = NULL;

#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //Invalid parameters?
   if(oid == NULL || length == 0)
   {
      curveInfo = NULL;
   }
#if (X509_SECP112R1_SUPPORT == ENABLED)
   //secp112r1 elliptic curve?
   else if(!oidComp(oid, length, SECP112R1_OID, sizeof(SECP112R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP112R2_SUPPORT == ENABLED)
   //secp112r2 elliptic curve?
   else if(!oidComp(oid, length, SECP112R2_OID, sizeof(SECP112R2_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP128R1_SUPPORT == ENABLED)
   //secp128r1 elliptic curve?
   else if(!oidComp(oid, length, SECP128R1_OID, sizeof(SECP128R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP128R2_SUPPORT == ENABLED)
   //secp128r2 elliptic curve?
   else if(!oidComp(oid, length, SECP128R2_OID, sizeof(SECP128R2_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP160K1_SUPPORT == ENABLED)
   //secp160k1 elliptic curve?
   else if(!oidComp(oid, length, SECP160K1_OID, sizeof(SECP160K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP160R1_SUPPORT == ENABLED)
   //secp160r1 elliptic curve?
   else if(!oidComp(oid, length, SECP160R1_OID, sizeof(SECP160R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP160R2_SUPPORT == ENABLED)
   //secp160r2 elliptic curve?
   else if(!oidComp(oid, length, SECP160R2_OID, sizeof(SECP160R2_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP192K1_SUPPORT == ENABLED)
   //secp192k1 elliptic curve?
   else if(!oidComp(oid, length, SECP192K1_OID, sizeof(SECP192K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP192R1_SUPPORT == ENABLED)
   //secp192r1 elliptic curve?
   else if(!oidComp(oid, length, SECP192R1_OID, sizeof(SECP192R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP224K1_SUPPORT == ENABLED)
   //secp224k1 elliptic curve?
   else if(!oidComp(oid, length, SECP224K1_OID, sizeof(SECP224K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP224R1_SUPPORT == ENABLED)
   //secp224r1 elliptic curve?
   else if(!oidComp(oid, length, SECP224R1_OID, sizeof(SECP224R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP256K1_SUPPORT == ENABLED)
   //secp256k1 elliptic curve?
   else if(!oidComp(oid, length, SECP256K1_OID, sizeof(SECP256K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   else if(!oidComp(oid, length, SECP256R1_OID, sizeof(SECP256R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   else if(!oidComp(oid, length, SECP384R1_OID, sizeof(SECP384R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP521R1_SUPPORT == ENABLED)
   //secp521r1 elliptic curve?
   else if(!oidComp(oid, length, SECP521R1_OID, sizeof(SECP521R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP160R1_SUPPORT == ENABLED)
   //brainpoolP160r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP160R1_OID, sizeof(BRAINPOOLP160R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP192R1_SUPPORT == ENABLED)
   //brainpoolP192r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP192R1_OID, sizeof(BRAINPOOLP192R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP224R1_SUPPORT == ENABLED)
   //brainpoolP224r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP224R1_OID, sizeof(BRAINPOOLP224R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP256R1_OID, sizeof(BRAINPOOLP256R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP320R1_SUPPORT == ENABLED)
   //brainpoolP320r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP320R1_OID, sizeof(BRAINPOOLP320R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP384R1_OID, sizeof(BRAINPOOLP384R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP512R1_OID, sizeof(BRAINPOOLP512R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
   else
   {
      curveInfo = NULL;
   }
#endif

   //Return the elliptic curve domain parameters, if any
   return curveInfo;
}

#endif
