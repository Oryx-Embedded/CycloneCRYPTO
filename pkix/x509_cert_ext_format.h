/**
 * @file x509_cert_ext_format.h
 * @brief X.509 extension formatting
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

#ifndef _X509_CERT_EXT_FORMAT_H
#define _X509_CERT_EXT_FORMAT_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//X.509 related functions
error_t x509FormatExtensions(const X509Extensions *extensions,
   const X509SubjectKeyId *subjectKeyId, const X509AuthKeyId *authKeyId,
   uint8_t *output, size_t *written);

error_t x509FormatExtension(const X509Extension *extension, uint8_t *output,
   size_t *written);

error_t x509FormatBasicConstraints(const X509BasicConstraints *basicConstraints,
   uint8_t *output, size_t *written);

error_t x509FormatKeyUsage(const X509KeyUsage *keyUsage, uint8_t *output,
   size_t *written);

error_t x509FormatExtendedKeyUsage(const X509ExtendedKeyUsage *extKeyUsage,
   uint8_t *output, size_t *written);

error_t x509FormatKeyPurposes(uint16_t bitmap, uint8_t *output,
   size_t *written);

error_t x509FormatSubjectAltName(const X509SubjectAltName *subjectAltName,
   uint8_t *output, size_t *written);

error_t x509FormatSubjectKeyId(const X509SubjectKeyId *subjectKeyId,
   uint8_t *output, size_t *written);

error_t x509FormatAuthorityKeyId(const X509AuthKeyId *authKeyId,
   uint8_t *output, size_t *written);

error_t x509FormatNsCertType(const X509NsCertType *nsCertType,
   uint8_t *output, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
