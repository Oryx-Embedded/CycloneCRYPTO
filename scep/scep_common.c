/**
 * @file scep_common.c
 * @brief SCEP common definitions
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
#define TRACE_LEVEL SCEP_TRACE_LEVEL

//Dependencies
#include "scep/scep_client.h"
#include "scep/scep_common.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)

//Message Type OID (2.16.840.1.113733.1.9.2)
const uint8_t SCEP_MESSAGE_TYPE_OID[10] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x02};
//PKI Status OID (2.16.840.1.113733.1.9.3)
const uint8_t SCEP_PKI_STATUS_OID[10] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x03};
//Fail Info OID (2.16.840.1.113733.1.9.4)
const uint8_t SCEP_FAIL_INFO_OID[10] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x04};
//Sender Nonce OID (2.16.840.1.113733.1.9.5)
const uint8_t SCEP_SENDER_NONCE_OID[10] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x05};
//Recipient Nonce OID (2.16.840.1.113733.1.9.6)
const uint8_t SCEP_RECIPIENT_NONCE_OID[10] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x06};
//Transaction ID OID (2.16.840.1.113733.1.9.7)
const uint8_t SCEP_TRANSACTION_ID_OID[10] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x07};
//Fail Info Text OID (1.3.6.1.5.5.7.24.1)
const uint8_t SCEP_FAIL_INFO_TEXT_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x18, 0x01};

#endif
