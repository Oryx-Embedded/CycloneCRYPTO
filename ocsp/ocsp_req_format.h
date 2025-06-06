/**
 * @file ocsp_req_format.h
 * @brief OCSP request formatting
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

#ifndef _OCSP_REQ_FORMAT_H
#define _OCSP_REQ_FORMAT_H

//Dependencies
#include "ocsp/ocsp_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//OCSP related functions
error_t ocspFormatRequest(const OcspRequest *request, uint8_t *output,
   size_t *written);

error_t ocspFormatTbsRequest(const OcspTbsRequest *tbsRequest, uint8_t *output,
   size_t *written);

error_t ocspFormatVersion(OcspVersion version, uint8_t *output,
   size_t *written);

error_t ocspFormatRequestList(const OcspSingleRequest *requestList,
   uint_t numRequests, uint8_t *output, size_t *written);

error_t ocspFormatSingleRequest(const OcspSingleRequest *singleRequest,
   uint8_t *output, size_t *written);

error_t ocspFormatCertId(const OcspCertId *certId, uint8_t *output,
   size_t *written);

error_t ocspFormatHashAlgo(const OcspCertId *certId, uint8_t *output,
   size_t *written);

error_t ocspFormatRequestExtensions(const OcspExtensions *extensions,
   uint8_t *output, size_t *written);

error_t ocspFormatNonceExtension(const X509OctetString *nonce, uint8_t *output,
   size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
