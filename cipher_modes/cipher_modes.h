/**
 * @file cipher_modes.h
 * @brief Block cipher modes of operation
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.2.4
 **/

#ifndef _CIPHER_MODES_H
#define _CIPHER_MODES_H

//Dependencies
#include "core/crypto.h"

//ECB mode support?
#if (ECB_SUPPORT == ENABLED)
   #include "cipher_modes/ecb.h"
#endif

//CBC mode support?
#if (CBC_SUPPORT == ENABLED)
   #include "cipher_modes/cbc.h"
#endif

//CFB mode support?
#if (CFB_SUPPORT == ENABLED)
   #include "cipher_modes/cfb.h"
#endif

//OFB mode support?
#if (OFB_SUPPORT == ENABLED)
   #include "cipher_modes/ofb.h"
#endif

//CTR mode support?
#if (CTR_SUPPORT == ENABLED)
   #include "cipher_modes/ctr.h"
#endif

//XTS mode support?
#if (XTS_SUPPORT == ENABLED)
   #include "cipher_modes/xts.h"
#endif

#endif
