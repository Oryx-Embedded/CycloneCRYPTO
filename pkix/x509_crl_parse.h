/**
 * @file x509_crl_parse.h
 * @brief CRL (Certificate Revocation List) parsing
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

#ifndef _X509_CRL_PARSE_H
#define _X509_CRL_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//CRL related functions
error_t x509ParseCrl(const uint8_t *data, size_t length,
   X509CrlInfo *crlInfo);

error_t x509ParseTbsCertList(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertList *tbsCertList);

error_t x509ParseCrlVersion(const uint8_t *data, size_t length,
   size_t *totalLength, X509Version *version);

error_t x509ParseRevokedCertificates(const uint8_t *data, size_t length,
   size_t *totalLength, X509TbsCertList *tbsCertList);

error_t x509ParseRevokedCertificate(const uint8_t *data, size_t length,
   size_t *totalLength, X509RevokedCertificate *revokedCertificate);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
