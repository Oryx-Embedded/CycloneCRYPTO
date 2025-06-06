/**
 * @file ascon.c
 * @brief Ascon-Based lightweight cryptography
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
 * @section Description
 *
 * Ascon is a family of lightweight cryptographic algorithms: an AEAD
 * algorithm (Ascon-AEAD128), a hash function (Ascon-Hash256), an XOF function
 * (Ascon-XOF128) and a customized XOF function (Ascon-CXOF128). The Ascon
 * family is designed to operate efficiently in constrained environments. Refer
 * to NIST SP 800-232 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "lwc/ascon.h"

//Check crypto library configuration
#if (ASCON_AEAD128_SUPPORT == ENABLED || ASCON_HASH256_SUPPORT == ENABLED || \
   ASCON_XOF128_SUPPORT == ENABLED || ASCON_CXOF128_SUPPORT == ENABLED)

//Round constants
static const uint8_t rc[16] =
{
   0x3C, 0x2D, 0x1E, 0x0F, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B
};


/**
 * @brief Ascon-p[rnd] permutation
 * @param[in,out] s Ascon state
 * @param[in] nr Number of rounds to be applied (1 to 16)
 **/

void asconP(AsconState *s, uint_t nr)
{
   uint_t i;
   uint32_t w1;
   uint32_t w2;

   //The standard specifies additional Ascon permutations by providing round
   //constants for up to 16 rounds to accommodate potential functionality
   //extensions in the future
   for(i = 16 - nr; i < 16; i++)
   {
      //Constant addition layer (PC)
      s->x[4] ^= rc[i];

      //Substitution layer (PS)
      s->x[0] ^= s->x[8];
      s->x[1] ^= s->x[9];
      s->x[8] ^= s->x[6];
      s->x[9] ^= s->x[7];
      s->x[4] ^= s->x[2];
      s->x[5] ^= s->x[3];

      w1 = s->x[0] & ~s->x[8];
      w2 = s->x[1] & ~s->x[9];
      s->x[0] ^= s->x[4] & ~s->x[2];
      s->x[1] ^= s->x[5] & ~s->x[3];
      s->x[4] ^= s->x[8] & ~s->x[6];
      s->x[5] ^= s->x[9] & ~s->x[7];
      s->x[8] ^= s->x[2] & ~s->x[0];
      s->x[9] ^= s->x[3] & ~s->x[1];
      s->x[2] ^= s->x[6] & ~s->x[4];
      s->x[3] ^= s->x[7] & ~s->x[5];
      s->x[6] ^= w1;
      s->x[7] ^= w2;

      s->x[2] ^= s->x[0];
      s->x[3] ^= s->x[1];
      s->x[0] ^= s->x[8];
      s->x[1] ^= s->x[9];
      s->x[6] ^= s->x[4];
      s->x[7] ^= s->x[5];
      s->x[4] = ~s->x[4];
      s->x[5] = ~s->x[5];

      //Linear diffusion layer (PL)
      w1 = s->x[0];
      w2 = s->x[1];
      s->x[0] = w1 ^ (w1 >> 19) ^ (w2 << 13) ^ (w1 >> 28) ^ (w2 << 4);
      s->x[1] = w2 ^ (w2 >> 19) ^ (w1 << 13) ^ (w2 >> 28) ^ (w1 << 4);

      w1 = s->x[2];
      w2 = s->x[3];
      s->x[2] = w1 ^ (w2 >> 29) ^ (w1 << 3) ^ (w2 >> 7) ^ (w1 << 25);
      s->x[3] = w2 ^ (w1 >> 29) ^ (w2 << 3) ^ (w1 >> 7) ^ (w2 << 25);

      w1 = s->x[4];
      w2 = s->x[5];
      s->x[4] = w1 ^ (w1 >> 1) ^ (w2 << 31) ^ (w1 >> 6) ^ (w2 << 26);
      s->x[5] = w2 ^ (w2 >> 1) ^ (w1 << 31) ^ (w2 >> 6) ^ (w1 << 26);

      w1 = s->x[6];
      w2 = s->x[7];
      s->x[6] = w1 ^ (w1 >> 10) ^ (w2 << 22) ^ (w1 >> 17) ^ (w2 << 15);
      s->x[7] = w2 ^ (w2 >> 10) ^ (w1 << 22) ^ (w2 >> 17) ^ (w1 << 15);

      w1 = s->x[8];
      w2 = s->x[9];
      s->x[8] = w1 ^ (w1 >> 7) ^ (w2 << 25) ^ (w2 >> 9) ^ (w1 << 23);
      s->x[9] = w2 ^ (w2 >> 7) ^ (w1 << 25) ^ (w1 >> 9) ^ (w2 << 23);
   }
}

#endif
