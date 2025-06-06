/**
 * @file mpi_mips_gcc.S
 * @brief MIPS assembly routines for GCC compiler
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

/*
 * Macros
 */

.macro         MUL_ACC_CORE
               lw    $t3, 0($a1)
               addiu $a1, $a1, 4
               multu $t3, $a3
               mflo  $t1
               mfhi  $t2
               lw    $t3, 0($a0)
               addu  $t3, $t3, $t0
               sltu  $t0, $t3, $t0
               addu  $t3, $t3, $t1
               sltu  $t1, $t3, $t1
               addu  $t0, $t0, $t1
               addu  $t0, $t0, $t2
               sw    $t3, 0($a0)
               addiu $a0, $a0, 4
.endm

/*
 * Exports
 */

.global mpiMulAccCore

.set nomips16
.set noreorder
.set noat
.text

/*
 * Multiply-accumulate operation
 */

.ent mpiMulAccCore

mpiMulAccCore:
               li    $t0, 0
               sltiu $t1, $a2, 16
               bne   $t1, $zero, next1
               nop
loop1:
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               addiu $a2, $a2, -16
               sltiu $t1, $a2, 16
               beq   $t1, $zero, loop1
               nop
next1:
               sltiu $t1, $a2, 8
               bne   $t1, $zero, next2
               nop
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               addiu $a2, $a2, -8
next2:
               sltiu $t1, $a2, 4
               bne   $t1, $zero, next3
               nop
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               addiu $a2, $a2, -4
next3:
               sltiu $t1, $a2, 2
               bne   $t1, $zero, next4
               nop
               MUL_ACC_CORE
               MUL_ACC_CORE
               addiu $a2, $a2, -2
next4:
               sltiu $t1, $a2, 1
               bne   $t1, $zero, next5
               nop
               MUL_ACC_CORE
next5:
               beq   $t0, $zero, next6
               nop
loop2:
               lw    $t3, 0($a0)
               addu  $t3, $t3, $t0
               sltu  $t0, $t3, $t0
               sw    $t3, 0($a0)
               addiu $a0, $a0, 4
               bne   $t0, $zero, loop2
               nop
next6:
               jr    $ra
               nop

.end mpiMulAccCore
