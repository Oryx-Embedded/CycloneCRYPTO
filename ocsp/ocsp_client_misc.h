/**
 * @file ocsp_client_misc.h
 * @brief Helper functions for OCSP client
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.3.0
 **/

#ifndef _OCSP_CLIENT_MISC_H
#define _OCSP_CLIENT_MISC_H

//Dependencies
#include "core/net.h"
#include "ocsp/ocsp_client.h"
#include "date_time.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//OCSP client related functions
error_t ocspClientGenerateNonce(OcspClientContext *context);
error_t ocspClientFormatHeader(OcspClientContext *context);

error_t ocspClientFormatRequest(OcspClientContext *context, const char_t *cert,
   size_t certLen, const char_t *issuerCert, size_t issuerCertLen);

error_t ocspClientParseHeader(OcspClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
