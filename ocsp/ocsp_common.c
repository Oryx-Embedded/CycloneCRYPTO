/**
 * @file ocsp_common.c
 * @brief OCSP common definitions
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

//Switch to the appropriate trace level
#define TRACE_LEVEL OCSP_TRACE_LEVEL

//Dependencies
#include "ocsp/ocsp_common.h"
#include "encoding/oid.h"

//Check crypto library configuration
#if (OCSP_SUPPORT == ENABLED)

//PKIX OCSP Basic OID (1.3.6.1.5.5.7.48.1.1)
const uint8_t PKIX_OCSP_BASIC_OID[9] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01};
//PKIX OCSP Nonce OID (1.3.6.1.5.5.7.48.1.2)
const uint8_t PKIX_OCSP_NONCE_OID[9] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02};


/**
 * @brief Hash algorithm selection
 * @return Pointer to the preferred hash algorithm
 **/

const HashAlgo *ocspSelectHashAlgo(void)
{
   const HashAlgo *hashAlgo;

#if (OCSP_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //Select SHA-1 hash algorithm
   hashAlgo = SHA1_HASH_ALGO;
#elif (OCSP_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //Select SHA-256 hash algorithm
   hashAlgo = SHA256_HASH_ALGO;
#elif (OCSP_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //Select SHA-384 hash algorithm
   hashAlgo = SHA384_HASH_ALGO;
#elif (OCSP_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //Select SHA-512 hash algorithm
   hashAlgo = SHA512_HASH_ALGO;
#else
   //Just for sanity
   hashAlgo = NULL;
#endif

   //Return the preferred hash algorithm
   return hashAlgo;
}


/**
 * @brief Get the hash algorithm that matches the specified identifier
 * @param[in] oid Hash algorithm OID
 * @param[in] length Length of the hash algorithm OID, in bytes
 * @return Pointer to the hash algorithm
 **/

const HashAlgo *ocspGetHashAlgo(const uint8_t *oid, size_t length)
{
   const HashAlgo *hashAlgo;

#if (OCSP_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //SHA-1 hash algorithm identifier?
   if(OID_COMP(oid, length, SHA1_OID) == 0)
   {
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (OCSP_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //SHA-256 hash algorithm identifier?
   if(OID_COMP(oid, length, SHA256_OID) == 0)
   {
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (OCSP_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //SHA-384 hash algorithm identifier?
   if(OID_COMP(oid, length, SHA384_OID) == 0)
   {
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (OCSP_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //SHA-512 hash algorithm identifier?
   if(OID_COMP(oid, length, SHA512_OID) == 0)
   {
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown hash algorithm identifier?
   {
      hashAlgo = NULL;
   }

   //Return the hash algorithm that matches the specified OID
   return hashAlgo;
}

#endif
