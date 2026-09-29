/**
 * @file kdf_algorithms.h
 * @brief Collection of KDF algorithms
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

#ifndef _KDF_ALGORITHMS_H
#define _KDF_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//HKDF support?
#if (HKDF_SUPPORT == ENABLED)
   #include "kdf/hkdf.h"
#endif

//KBKDF support?
#if (KBKDF_SUPPORT == ENABLED)
   #include "kdf/kbkdf.h"
#endif

//PBKDF support?
#if (PBKDF_SUPPORT == ENABLED)
   #include "kdf/pbkdf.h"
#endif

//Concat KDF support?
#if (CONCAT_KDF_SUPPORT == ENABLED)
   #include "kdf/concat_kdf.h"
#endif

//One-Step KDF support?
#if (ONE_STEP_KDF_SUPPORT == ENABLED)
   #include "kdf/one_step_kdf.h"
#endif

//ANSI X9.63 KDF support?
#if (X963_KDF_SUPPORT == ENABLED)
   #include "kdf/x963_kdf.h"
#endif

//TLS KDF support?
#if (TLS_KDF_SUPPORT == ENABLED)
   #include "kdf/tls_kdf.h"
#endif

//SSH KDF support?
#if (SSH_KDF_SUPPORT == ENABLED)
   #include "kdf/ssh_kdf.h"
#endif

//IKE KDF support?
#if (IKE_KDF_SUPPORT == ENABLED)
   #include "kdf/ike_kdf.h"
#endif

//bcrypt support?
#if (BCRYPT_SUPPORT == ENABLED)
   #include "kdf/bcrypt.h"
#endif

//scrypt support?
#if (SCRYPT_SUPPORT == ENABLED)
   #include "kdf/scrypt.h"
#endif

//MD5-crypt support?
#if (MD5_CRYPT_SUPPORT == ENABLED)
   #include "kdf/md5_crypt.h"
#endif

//SHA-crypt support?
#if (SHA_CRYPT_SUPPORT == ENABLED)
   #include "kdf/sha_crypt.h"
#endif

#endif
