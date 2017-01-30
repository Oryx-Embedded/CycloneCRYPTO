/**
 * @file pem.h
 * @brief PEM (Privacy-Enhanced Mail)
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
 * @version 1.7.6
 **/

#ifndef _PEM_H
#define _PEM_H

//Dependencies
#include "crypto.h"
#include "dh.h"
#include "rsa.h"
#include "dsa.h"
#include "ec.h"

//PEM format decoding functions
error_t pemReadDhParameters(const char_t *input, size_t length, DhParameters *params);

error_t pemReadRsaPrivateKey(const char_t *input, size_t length, RsaPrivateKey *key);
error_t pemReadDsaPrivateKey(const char_t *input, size_t length, DsaPrivateKey *key);

error_t pemReadEcParameters(const char_t *input, size_t length, EcDomainParameters *params);
error_t pemReadEcPrivateKey(const char_t *input, size_t length, Mpi *key);

error_t pemReadCertificate(const char_t **input, size_t *inputLength,
   uint8_t **output, size_t *outputSize, size_t *outputLength);

int_t pemSearchTag(const char_t *s, size_t sLen, const char_t *tag, size_t tagLen);

#endif
