/**
 * @file mpi.h
 * @brief MPI (Multiple Precision Integer Arithmetic)
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

#ifndef _MPI_H
#define _MPI_H

//Dependencies
#include <stdio.h>
#include "core/crypto.h"

//Maximum size of a multiple precision integer, in bits
#ifndef MPI_MAX_BITS
   #define MPI_MAX_BITS 4096
#elif (MPI_MAX_BITS < 0)
   #error MPI_MAX_BITS parameter is not valid
#endif

//Size of the MPI base type, in bits
#ifndef MPI_BITS_PER_WORD
   #define MPI_BITS_PER_WORD 32
#elif (MPI_BITS_PER_WORD != 8 || MPI_BITS_PER_WORD != 16 || MPI_BITS_PER_WORD != 32)
   #error MPI_BITS_PER_WORD parameter is not valid
#endif

//Maximum size of a multiple precision integer, in words
#define MPI_MAX_WORDS ((MPI_MAX_BITS + MPI_BITS_PER_WORD - 1) / MPI_BITS_PER_WORD)

//Size of the MPI base type, in bytes
#define MPI_BYTES_PER_WORD (MPI_BITS_PER_WORD / 8)

//MPI base types
#if (MPI_BITS_PER_WORD == 8)
   #define mpi_word_t uint8_t
   #define mpi_sword_t int8_t
   #define mpi_dword_t uint16_t
#elif (MPI_BITS_PER_WORD == 16)
   #define mpi_word_t uint16_t
   #define mpi_sword_t int16_t
   #define mpi_dword_t uint32_t
#elif (MPI_BITS_PER_WORD == 32)
   #define mpi_word_t uint32_t
   #define mpi_sword_t int32_t
   #define mpi_dword_t uint64_t
#endif

//Error code checking
#define MPI_CHECK(f) if((error = f) != NO_ERROR) goto end

//Miscellaneous macros
#define mpiIsEven(a) !mpiGetBitValue(a, 0)
#define mpiIsOdd(a) mpiGetBitValue(a, 0)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief MPI import/export format
 **/

typedef enum
{
   MPI_FORMAT_LITTLE_ENDIAN = 0,
   MPI_FORMAT_BIG_ENDIAN    = 1
} MpiFormat;


/**
 * @brief Arbitrary precision integer
 **/

typedef struct
{
   int_t sign;
   uint_t size;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   mpi_word_t *data;
#else
   mpi_word_t data[MPI_MAX_WORDS];
#endif
} Mpi;


//MPI related functions
void mpiInit(Mpi *r);
void mpiFree(Mpi *r);

error_t mpiGrow(Mpi *r, uint_t size);

uint_t mpiGetLength(const Mpi *a);
uint_t mpiGetByteLength(const Mpi *a);
uint_t mpiGetBitLength(const Mpi *a);

error_t mpiSetBitValue(Mpi *r, uint_t index, uint_t value);
uint_t mpiGetBitValue(const Mpi *a, uint_t index);

int_t mpiComp(const Mpi *a, const Mpi *b);
int_t mpiCompInt(const Mpi *a, mpi_sword_t b);
int_t mpiCompAbs(const Mpi *a, const Mpi *b);

error_t mpiCopy(Mpi *r, const Mpi *a);
error_t mpiSetValue(Mpi *r, mpi_sword_t a);

error_t mpiRand(Mpi *r, uint_t length, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t mpiRandRange(Mpi *r, const Mpi *p, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t mpiCheckProbablePrime(const Mpi *a);

error_t mpiImport(Mpi *r, const uint8_t *input, size_t length,
   MpiFormat format);

error_t mpiExport(const Mpi *a, uint8_t *output, size_t length,
   MpiFormat format);

error_t mpiAdd(Mpi *r, const Mpi *a, const Mpi *b);
error_t mpiAddInt(Mpi *r, const Mpi *a, mpi_sword_t b);

error_t mpiSub(Mpi *r, const Mpi *a, const Mpi *b);
error_t mpiSubInt(Mpi *r, const Mpi *a, mpi_sword_t b);

error_t mpiAddAbs(Mpi *r, const Mpi *a, const Mpi *b);
error_t mpiSubAbs(Mpi *r, const Mpi *a, const Mpi *b);

error_t mpiShiftLeft(Mpi *r, uint_t n);
error_t mpiShiftRight(Mpi *r, uint_t n);

error_t mpiMul(Mpi *r, const Mpi *a, const Mpi *b);
error_t mpiMulInt(Mpi *r, const Mpi *a, mpi_sword_t b);

error_t mpiDiv(Mpi *q, Mpi *r, const Mpi *a, const Mpi *b);
error_t mpiDivInt(Mpi *q, Mpi *r, const Mpi *a, mpi_sword_t b);

error_t mpiMod(Mpi *r, const Mpi *a, const Mpi *p);
error_t mpiAddMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p);
error_t mpiSubMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p);
error_t mpiMulMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p);
error_t mpiInvMod(Mpi *r, const Mpi *a, const Mpi *p);

error_t mpiExpMod(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p);
error_t mpiExpModFast(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p);
error_t mpiExpModRegular(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p);

error_t mpiMontgomeryMul(Mpi *r, const Mpi *a, const Mpi *b, uint_t k,
   const Mpi *p, Mpi *t);

error_t mpiMontgomeryRed(Mpi *r, const Mpi *a, uint_t k, const Mpi *p, Mpi *t);

void mpiMulAccCore(mpi_word_t *r, const mpi_word_t *a, int_t m,
   const mpi_word_t b);

void mpiDump(FILE *stream, const char_t *prepend, const Mpi *a);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
