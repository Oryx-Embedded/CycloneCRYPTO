; @file mpi_arm_v7m_iar.s
; @brief ARMv7-M (Cortex-M3/M4/M7) assembly routines for IAR EWARM compiler
;
; @section License
;
; SPDX-License-Identifier: GPL-2.0-or-later
;
; Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
;
; This file is part of CycloneCRYPTO Open.
;
; This program is free software; you can redistribute it and/or
; modify it under the terms of the GNU General Public License
; as published by the Free Software Foundation; either version 2
; of the License, or (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software Foundation,
; Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
;
; @author Oryx Embedded SARL (www.oryx-embedded.com)
; @version 2.5.2

;**********
;* Macros *
;**********

MUL_ACC_CORE   macro
               mov   r5, #0
               ldr   r6, [r1], #4
               umlal r4, r5, r6, r3
               ldr   r6, [r0]
               adds  r6, r6, r4
               adc   r4, r5, #0
               str   r6, [r0], #4
               endm

;***********
;* Exports *
;***********

               public mpiMulAccCore

               rseg  CODE:CODE(2)
               thumb

;*********************************
;* Multiply-accumulate operation *
;*********************************

mpiMulAccCore
               push  {r4-r6}
               mov   r4, #0
               cmp   r2, #8
               blo   next1
loop1
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               MUL_ACC_CORE
               sub   r2, r2, #8
               cmp   r2, #8
               bhs   loop1
next1
               cmp   r2, #1
               blo   next2
loop2
               MUL_ACC_CORE
               subs  r2, r2, #1
               bne   loop2
next2
               cbz   r4, next3
loop3
               ldr   r6, [r0]
               adds  r6, r6, r4
               str   r6, [r0], #4
               mov   r4, #0
               adcs  r4, r4, #0
               bne   loop3
next3
               pop   {r4-r6}
               bx    r14

               end
