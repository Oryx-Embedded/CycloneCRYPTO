/**
 * @file ocsp_resp_validate.h
 * @brief OCSP response validation
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

#ifndef _OCSP_RESP_VALIDATE_H
#define _OCSP_RESP_VALIDATE_H

//Dependencies
#include "ocsp/ocsp_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//OCSP related functions
error_t ocspValidateResponse(const OcspResponse *response,
   const X509CertInfo *certInfo, const X509CertInfo *issuerCertInfo,
   const uint8_t *nonce, size_t nonceLen);

error_t ocspCheckResponseSignature(const OcspBasicResponse *basicResponse,
   const X509CertInfo *issuerCertInfo);

error_t ocspCheckResponderCert(const OcspResponderId *responderId,
   const X509CertInfo *responderCertInfo, const X509CertInfo *issuerCertInfo);

error_t ocspCheckResponderId(const OcspResponderId *responderId,
   const X509CertInfo *issuerCertInfo);

error_t ocspCheckCertId(const OcspCertId *certId, const X509CertInfo *certInfo,
   const X509CertInfo *issuerCertInfo);

error_t ocspCheckValidity(const OcspSingleResponse *singleResponse);

error_t ocspCheckNonce(const OcspExtensions *extensions, const uint8_t *nonce,
   size_t nonceLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
