/**
 * @file x509_cert_parse.h
 * @brief X.509 certificate parsing
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

#ifndef _X509_CERT_PARSE_H
#define _X509_CERT_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//X.509 related functions
error_t x509ParseCertificate(const uint8_t *data, size_t length,
   X509CertInfo *certInfo);

error_t x509ParseCertificateEx(const uint8_t *data, size_t length,
   X509CertInfo *certInfo, const X509Options *options);

error_t x509ParseTbsCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertificate *tbsCert,
   const X509Options *options);

error_t x509ParseVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509Version *version);

error_t x509ParseSerialNumber(const uint8_t *data, size_t length,
   size_t *totalLength, X509SerialNumber *serialNumber);

error_t x509ParseIssuerUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength);

error_t x509ParseSubjectUniqueId(const uint8_t *data, size_t length,
   size_t *totalLength);

error_t x509ParseName(const uint8_t *data, size_t length,
   size_t *totalLength, X509Name *name);

error_t x509ParseNameAttribute(const uint8_t *data, size_t length,
   size_t *totalLength, X509NameAttribute *nameAttribute);

error_t x509ParseGeneralNames(const uint8_t *data, size_t length,
   X509GeneralName *generalNames, uint_t maxGeneralNames,
   uint_t *numGeneralNames);

error_t x509ParseGeneralName(const uint8_t *data, size_t length,
   size_t *totalLength, X509GeneralName *generalName);

error_t x509ParseGeneralSubtrees(const uint8_t *data, size_t length);

error_t x509ParseGeneralSubtree(const uint8_t *data, size_t length,
   size_t *totalLength, X509GeneralName *generalName);

error_t x509ParseValidity(const uint8_t *data, size_t length,
   size_t *totalLength, X509Validity *validity);

error_t x509ParseTime(const uint8_t *data, size_t length,
   size_t *totalLength, DateTime *dateTime);

error_t x509ParseTimeString(const uint8_t *data, size_t length, uint_t type,
   DateTime *dateTime);

error_t x509ParseInt(const uint8_t *data, size_t length, uint_t *value);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
