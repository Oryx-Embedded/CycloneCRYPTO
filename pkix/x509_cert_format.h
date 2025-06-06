/**
 * @file x509_cert_format.h
 * @brief X.509 certificate formatting
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

#ifndef _X509_CERT_FORMAT_H
#define _X509_CERT_FORMAT_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//X.509 related functions
error_t x509FormatTbsCertificate(const PrngAlgo *prngAlgo, void *prngContext,
   const X509SerialNumber *serialNumber, const X509SignAlgoId *signatureAlgo,
   const X509Name *issuer, const X509Validity *validity, const X509Name *subject,
   const X509SubjectPublicKeyInfo *subjectPublicKeyInfo, const void *publicKey,
   const X509Extensions *extensions, const X509AuthKeyId *authKeyId,
   uint8_t *output, size_t *written);

error_t x509FormatVersion(X509Version version, uint8_t *output,
   size_t *written);

error_t x509FormatSerialNumber(const PrngAlgo *prngAlgo, void *prngContext,
   const X509SerialNumber *serialNumber, uint8_t *output, size_t *written);

error_t x509FormatName(const X509Name *name, uint8_t *output, size_t *written);

error_t x509FormatNameAttribute(const X509NameAttribute *nameAttribute,
   uint8_t *output, size_t *written);

error_t x509FormatValidity(const X509Validity *validity, uint8_t *output,
   size_t *written);

error_t x509FormatTime(const DateTime *dateTime, uint8_t *output,
   size_t *written);

error_t x509FormatTimeString(const DateTime *dateTime, uint_t type,
   char_t *output);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
