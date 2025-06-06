/**
 * @file scep_client_misc.h
 * @brief Helper functions for SCEP client
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

#ifndef _SCEP_CLIENT_MISC_H
#define _SCEP_CLIENT_MISC_H

//Dependencies
#include "core/net.h"
#include "scep/scep_client.h"
#include "pkcs7/pkcs7_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SCEP client related functions
error_t scepClientSelectContentEncrAlgo(ScepClientContext *context,
   Pkcs7ContentEncrAlgo *contentEncrAlgo);

error_t scepClientSelectSignatureAlgo(ScepClientContext *context,
   X509SignAlgoId *signatureAlgo);

error_t scepClientParseCaCert(ScepClientContext *context,
   X509CertInfo *certInfo);

error_t scepClientVerifyCaCert(ScepClientContext *context);

error_t scepClientGenerateTransactionId(ScepClientContext *context);
error_t scepClientGenerateCsr(ScepClientContext *context);
error_t scepClientGenerateSelfSignedCert(ScepClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
