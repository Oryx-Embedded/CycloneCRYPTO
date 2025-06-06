/**
 * @file scep_debug.c
 * @brief Data logging functions for debugging purpose (SCEP)
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
#include "scep/scep_debug.h"
#include "debug.h"

//Check crypto library configuration
#if (SCEP_CLIENT_SUPPORT == ENABLED)

//SCEP message types
const ScepParamName scepMessageTypeList[] =
{
   {SCEP_MSG_TYPE_RESERVED,    "Reserved"},
   {SCEP_MSG_TYPE_CERT_REP,    "CertRep"},
   {SCEP_MSG_TYPE_RENEWAL_REQ, "RenewalReq"},
   {SCEP_MSG_TYPE_PKCS_REQ,    "PKCSReq"},
   {SCEP_MSG_TYPE_CERT_POLL,   "CertPoll"},
   {SCEP_MSG_TYPE_GET_CERT,    "GetCert"},
   {SCEP_MSG_TYPE_GET_CRL,     "GetCRL"}
};

//PKI status
const ScepParamName scepPkiStatusList[] =
{
   {SCEP_PKI_STATUS_SUCCESS, "SUCCESS"},
   {SCEP_PKI_STATUS_FAILURE, "FAILURE"},
   {SCEP_PKI_STATUS_PENDING, "PENDING"},
};

//Failure reasons
const ScepParamName scepFailInfoList[] =
{
   {SCEP_FAIL_INFO_BAD_ALG,           "badAlg"},
   {SCEP_FAIL_INFO_BAD_MESSAGE_CHECK, "badMessageCheck"},
   {SCEP_FAIL_INFO_BAD_REQUEST,       "badRequest"},
   {SCEP_FAIL_INFO_BAD_TIME,          "badTime"},
   {SCEP_FAIL_INFO_BAD_CERT_ID,       "badCertId"}
};


/**
 * @brief Dump SCEP message type
 * @param[in] messageType SCEP message type
 **/

void scepDumpMessageType(uint_t messageType)
{
#if (TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   const char_t *name;

   //Convert the SCEP message type to string representation
   name = scepGetParamName(messageType, scepMessageTypeList,
      arraysize(scepMessageTypeList));

   //The messageType attribute specifies the type of operation performed by
   //the transaction
   TRACE_DEBUG("messageType = %u (%s)\r\n", messageType, name);
#endif
}


/**
 * @brief Dump PKI status
 * @param[in] pkiStatus PKI status
 **/

void scepDumpPkiStatus(uint_t pkiStatus)
{
#if (TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   const char_t *name;

   //Convert the PKI status to string representation
   name = scepGetParamName(pkiStatus, scepPkiStatusList,
      arraysize(scepPkiStatusList));

   //The pkiStatus attribute specifies transaction status information
   TRACE_DEBUG("pkiStatus = %u (%s)\r\n", pkiStatus, name);
#endif
}


/**
 * @brief Dump failure reason
 * @param[in] failInfo SFailure reason
 **/

void scepDumpFailInfo(uint_t failInfo)
{
#if (TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   const char_t *name;

   //Convert the failure reason to string representation
   name = scepGetParamName(failInfo, scepFailInfoList,
      arraysize(scepFailInfoList));

   //The failInfo attribute specifies the failure reason
   TRACE_DEBUG("failInfo = %u (%s)\r\n", failInfo, name);
#endif
}


/**
 * @brief Convert a parameter to string representation
 * @param[in] value Parameter value
 * @param[in] paramList List of acceptable parameters
 * @param[in] paramListLen Number of entries in the list
 * @return NULL-terminated string describing the parameter
 **/

const char_t *scepGetParamName(uint_t value, const ScepParamName *paramList,
   size_t paramListLen)
{
   uint_t i;

   //Default name for unknown values
   static const char_t defaultName[] = "Unknown";

   //Loop through the list of acceptable parameters
   for(i = 0; i < paramListLen; i++)
   {
      if(paramList[i].value == value)
         return paramList[i].name;
   }

   //Unknown value
   return defaultName;
}

#endif
