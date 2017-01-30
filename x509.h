/**
 * @file x509.h
 * @brief X.509 certificate parsing and verification
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
 * @version 1.7.6
 **/

#ifndef _X509_H
#define _X509_H

//Dependencies
#include "crypto.h"
#include "date_time.h"
#include "rsa.h"
#include "dsa.h"
#include "ec.h"


/**
 * @brief X.509 versions
 **/

typedef enum
{
   X509_VERSION_1 = 0x00,
   X509_VERSION_2 = 0x01,
   X509_VERSION_3 = 0x02,
} X509Version;


/**
 * @brief Issuer or subject name
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   const char_t *commonName;
   size_t commonNameLen;
   const char_t *surname;
   size_t surnameLen;
   const char_t *serialNumber;
   size_t serialNumberLen;
   const char_t *countryName;
   size_t countryNameLen;
   const char_t *localityName;
   size_t localityNameLen;
   const char_t *stateOrProvinceName;
   size_t stateOrProvinceNameLen;
   const char_t *organizationName;
   size_t organizationNameLen;
   const char_t *organizationalUnitName;
   size_t organizationalUnitNameLen;
   const char_t *title;
   size_t titleLen;
   const char_t *name;
   size_t nameLen;
   const char_t *givenName;
   size_t givenNameLen;
   const char_t *initials;
   size_t initialsLen;
   const char_t *generationQualifier;
   size_t generationQualifierLen;
   const char_t *dnQualifier;
   size_t dnQualifierLen;
   const char_t *pseudonym;
   size_t pseudonymLen;
} X509Name;


/**
 * @brief Validity
 **/

typedef struct
{
   DateTime notBefore;
   DateTime notAfter;
} X509Validity;


/**
 * @brief RSA public key
 **/

typedef struct
{
   const uint8_t *n;
   size_t nLen;
   const uint8_t *e;
   size_t eLen;
} X509RsaPublicKey;


/**
 * @brief DSA domain parameters
 **/

typedef struct
{
   const uint8_t *p;
   size_t pLen;
   const uint8_t *q;
   size_t qLen;
   const uint8_t *g;
   size_t gLen;
} X509DsaParameters;


/**
 * @brief DSA public key
 **/

typedef struct
{
   const uint8_t *y;
   size_t yLen;
} X509DsaPublicKey;


/**
 * @brief EC parameters
 **/

typedef struct
{
   const uint8_t *namedCurve;
   size_t namedCurveLen;
} X509EcParameters;


/**
 * @brief EC public key
 **/

typedef struct
{
   const uint8_t *q;
   size_t qLen;
} X509EcPublicKey;


/**
 * @brief Subject public key info
 **/

typedef struct
{
   const uint8_t *oid;
   size_t oidLen;
#if (RSA_SUPPORT == ENABLED)
   X509RsaPublicKey rsaPublicKey;
#endif
#if (DSA_SUPPORT == ENABLED)
   X509DsaParameters dsaParams;
   X509DsaPublicKey dsaPublicKey;
#endif
#if (EC_SUPPORT == ENABLED)
   X509EcParameters ecParams;
   X509EcPublicKey ecPublicKey;
#endif
} X509SubjectPublicKeyInfo;


/**
 * @brief Basic constraints
 **/

typedef struct
{
   bool_t ca;
   uint_t pathLenConstraint;
} X509BasicContraints;


/**
 * @brief X.509 certificate
 **/

typedef struct
{
   const uint8_t *tbsCertificate;
   size_t tbsCertificateLen;
   uint8_t version;
   const uint8_t *serialNumber;
   size_t serialNumberLen;
   X509Name issuer;
   X509Validity validity;
   X509Name subject;
   X509SubjectPublicKeyInfo subjectPublicKeyInfo;
   X509BasicContraints basicConstraints;
   const uint8_t *signatureAlgo;
   size_t signatureAlgoLen;
   const uint8_t *signatureValue;
   size_t signatureValueLen;
} X509CertificateInfo;


//X.509 related constants
extern const uint8_t X509_COMMON_NAME_OID[3];
extern const uint8_t X509_SURNAME_OID[3];
extern const uint8_t X509_SERIAL_NUMBER_OID[3];
extern const uint8_t X509_COUNTRY_NAME_OID[3];
extern const uint8_t X509_LOCALITY_NAME_OID[3];
extern const uint8_t X509_STATE_OR_PROVINCE_NAME_OID[3];
extern const uint8_t X509_ORGANIZATION_NAME_OID[3];
extern const uint8_t X509_ORGANIZATIONAL_UNIT_NAME_OID[3];
extern const uint8_t X509_TITLE_OID[3];
extern const uint8_t X509_NAME_OID[3];
extern const uint8_t X509_GIVEN_NAME_OID[3];
extern const uint8_t X509_INITIALS_OID[3];
extern const uint8_t X509_GENERATION_QUALIFIER_OID[3];
extern const uint8_t X509_DN_QUALIFIER_OID[3];
extern const uint8_t X509_PSEUDONYM_OID[3];

extern const uint8_t X509_SUBJECT_DIRECTORY_ATTR_OID[3];
extern const uint8_t X509_SUBJECT_KEY_ID_OID[3];
extern const uint8_t X509_KEY_USAGE_OID[3];
extern const uint8_t X509_SUBJECT_ALT_NAME_OID[3];
extern const uint8_t X509_ISSUER_ALT_NAME_OID[3];
extern const uint8_t X509_BASIC_CONSTRAINTS_OID[3];
extern const uint8_t X509_NAME_CONSTRAINTS_OID[3];
extern const uint8_t X509_CRL_DISTR_POINTS_OID[3];
extern const uint8_t X509_CERTIFICATE_POLICIES_OID[3];
extern const uint8_t X509_POLICY_MAPPINGS_OID[3];
extern const uint8_t X509_AUTHORITY_KEY_ID_OID[3];
extern const uint8_t X509_POLICY_CONSTRAINTS_OID[3];
extern const uint8_t X509_EXTENDED_KEY_USAGE_OID[3];
extern const uint8_t X509_FRESHEST_CRL_OID[3];
extern const uint8_t X509_INHIBIT_ANY_POLICY_OID[3];

//X.509 related functions
error_t x509ParseCertificate(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseTbsCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseSerialNumber(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseSignature(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseName(const uint8_t *data, size_t length,
   size_t *totalLength, X509Name *name);

error_t x509ParseValidity(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseTime(const uint8_t *data, size_t length,
   size_t *totalLength, DateTime *dateTime);

error_t x509ParseSubjectPublicKeyInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseAlgorithmIdentifier(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseRsaPublicKey(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo);

error_t x509ParseDsaParameters(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo);

error_t x509ParseDsaPublicKey(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo);

error_t x509ParseEcParameters(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo);

error_t x509ParseEcPublicKey(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo);

error_t x509ParseIssuerUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseSubjectUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseExtensions(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseBasicConstraints(const uint8_t *data,
   size_t length, X509CertificateInfo *certInfo);

error_t x509ParseSignatureAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseSignatureValue(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseInt(const uint8_t *data, size_t length, uint_t *value);

error_t x509ReadRsaPublicKey(const X509CertificateInfo *certInfo, RsaPublicKey *key);
error_t x509ReadDsaPublicKey(const X509CertificateInfo *certInfo, DsaPublicKey *key);

error_t x509ValidateCertificate(const X509CertificateInfo *certInfo,
   const X509CertificateInfo *issuerCertInfo);

#endif
