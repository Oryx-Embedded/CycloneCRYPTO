/**
 * @file x509_cert_parse.h
 * @brief X.509 certificate parsing
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

#ifndef _X509_CERT_PARSE_H
#define _X509_CERT_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "certificate/x509_common.h"

//C++ guard
#ifdef __cplusplus
   extern "C" {
#endif

//X.509 related functions
error_t x509ParseCertificate(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseTbsCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertificateInfo *certInfo);

error_t x509ParseVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509Version *version);

error_t x509ParseSerialNumber(const uint8_t *data, size_t length,
   size_t *totalLength, X509SerialNumber *serialNumber);

error_t x509ParseSignature(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignatureId *signature);

error_t x509ParseName(const uint8_t *data, size_t length,
   size_t *totalLength, X509Name *name);

error_t x509ParseNameAttribute(const uint8_t *data, size_t length,
   size_t *totalLength, X509NameAttribute *nameAttribute);

error_t x509ParseValidity(const uint8_t *data, size_t length,
   size_t *totalLength, X509Validity *validity);

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

error_t x509ParseBasicConstraints(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseNameConstraints(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParsePolicyConstraints(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParsePolicyMappings(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseInhibitAnyPolicy(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseKeyUsage(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseExtendedKeyUsage(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseSubjectAltName(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseGeneralSubtrees(const uint8_t *data, size_t length);

error_t x509ParseGeneralSubtree(const uint8_t *data, size_t length,
   size_t *totalLength, X509GeneralName *generalName);

error_t x509ParseGeneralName(const uint8_t *data, size_t length,
   size_t *totalLength, X509GeneralName *generalName);

error_t x509ParseSubjectKeyId(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseAuthorityKeyId(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseNsCertType(const uint8_t *data, size_t length,
   X509CertificateInfo *certInfo);

error_t x509ParseSignatureAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignatureId *signatureAlgo);

error_t x509ParseSignatureValue(const uint8_t *data, size_t length,
   size_t *totalLength, X509SignatureValue *signatureValue);

//C++ guard
#ifdef __cplusplus
   }
#endif

#endif
