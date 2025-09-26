/**
 * @file mpi_misc.c
 * @brief Helper routines for MPI
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
 * @version 2.5.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "mpi/mpi.h"
#include "mpi/mpi_misc.h"
#include "debug.h"

//Check crypto library configuration
#if (MPI_SUPPORT == ENABLED)


/**
 * @brief Montgomery multiplication
 * @param[out] r Resulting integer R = A * B / 2^k mod P
 * @param[in] a An integer A such as 0 <= A < 2^k
 * @param[in] b An integer B such as 0 <= B < 2^k
 * @param[in] k An integer k such as P < 2^k
 * @param[in] p Modulus P
 * @param[in] t An preallocated integer T (for internal operation)
 * @return Error code
 **/

error_t mpiMontgomeryMul(Mpi *r, const Mpi *a, const Mpi *b, uint_t k,
   const Mpi *p, Mpi *t)
{
   error_t error;
   uint_t i;
   uint_t n;
   mpi_word_t m;
   mpi_word_t q;

   //Use Newton's method to compute the inverse of P[0] mod 2^32
   for(m = p->data[0], i = 0; i < 4; i++)
   {
      m = m * (2U - m * p->data[0]);
   }

   //Precompute -1/P[0] mod 2^32;
   m = ~m + 1U;

   //We assume that B is always less than 2^k
   n = MIN(b->size, k);

   //Make sure T is large enough
   MPI_CHECK(mpiGrow(t, 2 * k + 1));
   //Let T = 0
   MPI_CHECK(mpiSetValue(t, 0));

   //Perform Montgomery multiplication
   for(i = 0; i < k; i++)
   {
      //Check current index
      if(i < a->size)
      {
         //Compute q = ((T[i] + A[i] * B[0]) * m) mod 2^32
         q = (t->data[i] + a->data[i] * b->data[0]) * m;
         //Compute T = T + A[i] * B
         mpiMulAccCore(t->data + i, b->data, n, a->data[i]);
      }
      else
      {
         //Compute q = (T[i] * m) mod 2^32
         q = t->data[i] * m;
      }

      //Compute T = T + q * P
      mpiMulAccCore(t->data + i, p->data, k, q);
   }

   //Compute R = T / 2^(32 * k)
   MPI_CHECK(mpiShiftRight(t, k * MPI_BITS_PER_WORD));
   MPI_CHECK(mpiCopy(r, t));

   //A final subtraction is required
   if(mpiComp(r, p) >= 0)
   {
      MPI_CHECK(mpiSub(r, r, p));
   }

end:
   //Return status code
   return error;
}


/**
 * @brief Montgomery reduction
 * @param[out] r Resulting integer R = A / 2^k mod P
 * @param[in] a An integer A such as 0 <= A < 2^k
 * @param[in] k An integer k such as P < 2^k
 * @param[in] p Modulus P
 * @param[in] t An preallocated integer T (for internal operation)
 * @return Error code
 **/

error_t mpiMontgomeryRed(Mpi *r, const Mpi *a, uint_t k, const Mpi *p, Mpi *t)
{
   mpi_word_t value;
   Mpi b;

   //Let B = 1
   value = 1;
   b.sign = 1;
   b.size = 1;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   b.data = &value;
#else
   b.data[0] = value;
#endif

   //Compute R = A / 2^k mod P
   return mpiMontgomeryMul(r, a, &b, k, p, t);
}


#if (MPI_ASM_SUPPORT == DISABLED)

/**
 * @brief Multiply-accumulate operation
 * @param[out] r Resulting integer
 * @param[in] a First operand A
 * @param[in] m Size of A in words
 * @param[in] b Second operand B
 **/

void mpiMulAccCore(mpi_word_t *r, const mpi_word_t *a, int_t m,
   const mpi_word_t b)
{
   int_t i;
   mpi_word_t c;
   mpi_word_t u;
   mpi_word_t v;
   mpi_dword_t p;

   //Clear variables
   c = 0;
   u = 0;
   v = 0;

   //Perform multiplication
   for(i = 0; i < m; i++)
   {
      p = (mpi_dword_t) a[i] * b;
      u = (mpi_word_t) p;
      v = (mpi_word_t) (p >> MPI_BITS_PER_WORD);

      u += c;

      if(u < c)
      {
         v++;
      }

      u += r[i];

      if(u < r[i])
      {
         v++;
      }

      r[i] = u;
      c = v;
   }

   //Propagate carry
   for(; c != 0; i++)
   {
      r[i] += c;
      c = (r[i] < c);
   }
}

#endif
#endif
