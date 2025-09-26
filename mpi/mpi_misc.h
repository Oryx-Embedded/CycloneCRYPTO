/**
 * @file mpi_misc.h
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

#ifndef _MPI_MISC_H
#define _MPI_MISC_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//MPI related functions
error_t mpiMontgomeryMul(Mpi *r, const Mpi *a, const Mpi *b, uint_t k,
   const Mpi *p, Mpi *t);

error_t mpiMontgomeryRed(Mpi *r, const Mpi *a, uint_t k, const Mpi *p, Mpi *t);

void mpiMulAccCore(mpi_word_t *r, const mpi_word_t *a, int_t m,
   const mpi_word_t b);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
