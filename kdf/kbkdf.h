/**
 * @file kbkdf.h
 * @brief SP 800-108 key derivation function
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.6
 **/

#ifndef _KBKDF_H
#define _KBKDF_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//KBKDF related functions
error_t kbkdfCounterHmac(const HashAlgo *hashAlgo, uint_t r, const uint8_t *ki,
   size_t kiLen, const uint8_t *fixedData, size_t fixedDataLen, uint8_t *ko,
   size_t koLen);

error_t kbkdfCounterCmac(const CipherAlgo *cipherAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen);

error_t kbkdfFeedbackHmac(const HashAlgo *hashAlgo, uint_t r, const uint8_t *ki,
   size_t kiLen, const uint8_t *iv, size_t ivLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen);

error_t kbkdfFeedbackCmac(const CipherAlgo *cipherAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *iv, size_t ivLen,
   const uint8_t *fixedData, size_t fixedDataLen, uint8_t *ko, size_t koLen);

error_t kbkdfDoublePipelineHmac(const HashAlgo *hashAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen);

error_t kbkdfDoublePipelineCmac(const CipherAlgo *cipherAlgo, uint_t r,
   const uint8_t *ki, size_t kiLen, const uint8_t *fixedData,
   size_t fixedDataLen, uint8_t *ko, size_t koLen);

error_t kbkdfKmac(uint_t strength, const uint8_t *ki, size_t kiLen,
   const uint8_t *context, size_t contextLen, const char_t *label,
   size_t labelLen, uint8_t *ko, size_t koLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
