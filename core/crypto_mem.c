/**
 * @file crypto_mem.c
 * @brief Secure memory operations
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

//Dependencies
#include "crypto.h"
#include "crypto_mem.h"

//Volatile pointer to the memset function
void * (* const volatile volatile_memset) (void *, int, size_t) = memset;


/**
 * @brief Securely erase a memory block
 * @param[out] p Pointer to the memory block to be erased
 * @param[in] n Number of bytes to erase
 **/

__weak_func void cryptoZeroizeMem(void *p, size_t n)
{
   //Zeroize memory
   volatile_memset(p, 0, n);
}


/**
 * @brief Constant-time comparison of two memory blocks
 * @param[in] p1 Pointer to the first memory block
 * @param[in] p2 Pointer to the second memory block
 * @param[in] n Length of the memory blocks, in bytes
 * @return 0 if the two blocks are identical, a non-zero value otherwise
 **/

uint_t cryptoCompMem(const void *p1, const void *p2, size_t n)
{
   size_t i;
   uint8_t mask;
   const uint8_t *a;
   const uint8_t *b;

   //Point to the memory blocks to compare
   a = (const uint8_t *) p1;
   b = (const uint8_t *) p2;

   //Compare the two memory blocks byte by byte, without any early exit
   for(mask = 0, i = 0; i < n; i++)
   {
      mask |= a[i] ^ b[i];
   }

   //The result is zero if and only if the two blocks are identical
   return mask;
}
