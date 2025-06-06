/**
 * @file key_exch_algorithms.h
 * @brief Collection of key exchange algorithms
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

#ifndef _KEY_EXCH_ALGORITHMS_H
#define _KEY_EXCH_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"

//Diffie-Hellman support?
#if (DH_SUPPORT == ENABLED)
   #include "pkc/dh.h"
#endif

//ECDH support?
#if (ECDH_SUPPORT == ENABLED)
   #include "ecc/ecdh.h"
#endif

//KEM support?
#if (KEM_SUPPORT == ENABLED)
   #include "pqc/kem.h"
#endif

#endif
