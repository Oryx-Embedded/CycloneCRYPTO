/**
 * @file pem_common.c
 * @brief PEM common definitions
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
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkix/pem_common.h"
#include "encoding/oid.h"
#include "encoding/base64.h"
#include "cipher/cipher_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (PEM_SUPPORT == ENABLED)


/**
 * @brief Convert PEM container to ASN.1 format
 * @param[in] input PEM string to decode
 * @param[in] inputLen Length of the PEM string to decode
 * @param[in] label Label indicating the type of data
 * @param[out] output ASN.1 data (optional parameter)
 * @param[out] outputLen Length of the ASN.1 data
 * @param[out] header PEM encapsulated header (optional parameter)
 * @param[out] consumed Total number of characters that have been consumed
 *   (optional parameter)
 **/

error_t pemDecodeFile(const char_t *input, size_t inputLen, const char_t *label,
   uint8_t *output, size_t *outputLen, PemHeader *header, size_t *consumed)
{
   error_t error;
   int_t i;
   int_t j;
   size_t n;

   //Check parameters
   if(input == NULL || label == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //The PEM container begins with a "-----BEGIN " line
   i = pemFindTag(input, inputLen, "-----BEGIN ", label, "-----");
   //Pre-encapsulation boundary not found?
   if(i < 0)
      return ERROR_END_OF_FILE;

   //Skip the pre-encapsulation boundary
   i += osStrlen("-----BEGIN -----") + osStrlen(label);

   //The PEM container ends with a "-----END " line
   j = pemFindTag(input + i, inputLen - i, "-----END ", label, "-----");
   //Post-encapsulation boundary not found?
   if(j < 0)
      return ERROR_INVALID_SYNTAX;

   //Parse PEM encapsulated header
   error = pemParseHeader(input + i, j, header, &n);
   //Any error to report?
   if(error)
      return error;

   //The contents of the PEM file is Base64-encoded
   error = base64Decode(input + i + n, j - n, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //The last parameter is optional
   if(consumed != NULL)
   {
      //Total number of characters that have been consumed
      *consumed = i + j + osStrlen("-----END -----") + osStrlen(label);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Convert ASN.1 data to PEM encoding
 * @param[in] input ASN.1 data to encode
 * @param[in] inputLen Length of the ASN.1 data to encode
 * @param[in] label Label indicating the type of data
 * @param[out] output Buffer where to store the PEM string (optional parameter)
 * @param[out] outputLen Length of the resulting PEM string
 **/

error_t pemEncodeFile(const void *input, size_t inputLen, const char_t *label,
   char_t *output, size_t *outputLen)
{
   size_t n;
   size_t labelLen;
   char_t *p;

   //Check parameters
   if(label == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if(input == NULL && output != NULL)
      return ERROR_INVALID_PARAMETER;

   //Calculate the length of the label
   labelLen = osStrlen(label);

   //Generators must wrap the Base64-encoded lines so that each line consists
   //of exactly 64 characters except for the final line, which will encode the
   //remainder of the data (refer to RFC 7468, section 2)
   base64EncodeMultiline(input, inputLen, output, &n, 64);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting PEM file without copying any data
   if(output != NULL)
   {
      //A PEM file starts with a pre-encapsulation boundary
      p = output + osStrlen("-----BEGIN -----\r\n") + labelLen;

      //Make room for the pre-encapsulation boundary
      osMemmove(p, output, n);

      //The type of data encoded is labeled depending on the type label in
      //the "-----BEGIN " line (refer to RFC 7468, section 2)
      osStrcpy(output, "-----BEGIN ");
      osStrcpy(output + 11, label);
      osMemcpy(p - 7, "-----\r\n", 7);

      //Generators must put the same label on the "-----END " line as the
      //corresponding "-----BEGIN " line
      osStrcpy(p + n, "\r\n-----END ");
      osStrcpy(p + n + 11, label);
      osStrcpy(p + n + labelLen + 11, "-----\r\n");
   }

   //Consider the length of the PEM encapsulation boundaries
   n += osStrlen("-----BEGIN -----\r\n") + labelLen;
   n += osStrlen("\r\n-----END -----\r\n") + labelLen;

   //Return the length of the PEM string (excluding the terminating NULL)
   *outputLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse PEM encapsulated header
 * @param[in] input PEM message body
 * @param[in] inputLen Length of the PEM message body
 * @param[in] header PEM encapsulated header (optional parameter)
 * @param[out] consumed Total number of bytes that have been consumed
 * @return Error code
 **/

error_t pemParseHeader(const char_t *input, size_t inputLen,
   PemHeader *header, size_t *consumed)
{
   size_t n;
   const char_t *end;
   PemString line;

   //The header parameter is optional
   if(header != NULL)
   {
      //Clear header fields
      osMemset(header, 0, sizeof(PemHeader));
   }

   //Total number of bytes that have been consumed
   *consumed = 0;

   //Parse PEM encapsulated header
   while(1)
   {
      //Extract a line from the PEM message body
      end = osMemchr(input, '\n', inputLen);
      //No end of line character detected?
      if(end == NULL)
         break;

      //Calculate the length of the line
      n = end - input + 1;

      //Point to the current line
      line.value = input;
      line.length = n;

      //Removes all leading and trailing whitespace from a string
      pemTrimWhitespace(&line);

      //Discard empty lines
      if(!pemCompareString(&line, ""))
      {
         //Each header field consists of a field name followed by a colon,
         //optional leading whitespace, and the field value
         if(pemFindChar(&line, ':') >= 0)
         {
            //Parse header field
            pemParseHeaderField(&line, header);
         }
         else
         {
            //We are done
            break;
         }
      }

      //Point to the next line
      input += n;
      inputLen -= n;
      *consumed += n;
   }

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Parse header field
 * @param[in] line Header field
 * @param[in] header PEM encapsulated header (optional parameter)
 **/

void pemParseHeaderField(PemString *line, PemHeader *header)
{
   PemString name;
   PemString arg1;
   PemString arg2;

   //Each header field consists of a field name followed by a colon,
   //optional leading whitespace, and the field value
   pemTokenizeString(line, ':', &name);

   //Removes all leading and trailing whitespace from the name
   pemTrimWhitespace(&name);

   //Check header field name
   if(pemCompareString(&name, "Proc-Type"))
   {
      //The "Proc-Type" encapsulated header field, required for all PEM
      //messages, identifies the type of processing performed on the
      //transmitted message (refer to RFC 1421, section 4.6.1.1)
      if(pemTokenizeString(line, ',', &arg1) &&
         pemTokenizeString(line, ',', &arg2))
      {
         //Removes all leading and trailing whitespace characters
         pemTrimWhitespace(&arg1);
         pemTrimWhitespace(&arg2);

         //Save arguments
         if(header != NULL)
         {
            header->procType.version = arg1;
            header->procType.type = arg2;
         }
      }
   }
   else if(pemCompareString(&name, "DEK-Info"))
   {
      //The "DEK-Info" encapsulated header field identifies the message text
      //encryption algorithm and mode, and also carries the IV used for message
      //encryption (refer to RFC 1421, section 4.6.1.3)
      if(pemTokenizeString(line, ',', &arg1) &&
         pemTokenizeString(line, ',', &arg2))
      {
         //Removes all leading and trailing whitespace characters
         pemTrimWhitespace(&arg1);
         pemTrimWhitespace(&arg2);

         //Save arguments
         if(header != NULL)
         {
            header->dekInfo.algo = arg1;
            header->dekInfo.iv = arg2;
         }
      }
   }
   else
   {
      //Unknown header field name
   }
}


/**
 * @brief Search a string for a given tag
 * @param[in] input String to search
 * @param[in] inputLen Length of the string to search
 * @param[in] tag1 First part of the tag (NULL-terminated string)
 * @param[in] tag2 Second part of the tag (NULL-terminated string)
 * @param[in] tag3 Third part of the tag (NULL-terminated string)
 * @return The index of the first occurrence of the tag in the string,
 *   or -1 if the tag does not appear in the string
 **/

int_t pemFindTag(const char_t *input, size_t inputLen, const char_t *tag1,
   const char_t *tag2, const char_t *tag3)
{
   size_t i;
   size_t j;
   size_t n1;
   size_t n2;
   size_t n3;
   int_t index;

   //Initialize index
   index = -1;

   //Calculate the length of the tag
   n1 = osStrlen(tag1);
   n2 = osStrlen(tag2);
   n3 = osStrlen(tag3);

   //Parse input string
   for(i = 0; (i + n1 + n2 + n3) <= inputLen; i++)
   {
      //Compare current substring with the given tag
      for(j = 0; j < (n1 + n2 + n3); j++)
      {
         if(j < n1)
         {
            if(input[i + j] != tag1[j])
               break;
         }
         else if(j < (n1 + n2))
         {
            if(input[i + j] != tag2[j - n1])
               break;
         }
         else
         {
            if(input[i + j] != tag3[j - n1 - n2])
               break;
         }
      }

      //Check whether the tag has been found
      if(j == (n1 + n2 + n3))
      {
         index = i;
         break;
      }
   }

   //Return the index of the first occurrence of the tag in the string
   return index;
}


/**
 * @brief Search a string for a given character
 * @param[in] s String to be scanned
 * @param[in] c Character to be searched
 * @return Index of the first occurrence of the character
 **/

int_t pemFindChar(const PemString *s, char_t c)
{
   int_t index;
   char_t *p;

   //Search the string for the specified character
   p = osMemchr(s->value, c, s->length);

   //Character found?
   if(p != NULL)
   {
      index = p - s->value;
   }
   else
   {
      index = -1;
   }

   //Return the index of the first occurrence of the character
   return index;
}


/**
 * @brief Compare a string against the supplied value
 * @param[in] string String to be compared
 * @param[in] value NULL-terminated string
 * @return Comparison result
 **/

bool_t pemCompareString(const PemString *string, const char_t *value)
{
   bool_t res;
   size_t n;

   //Initialize flag
   res = FALSE;

   //Valid NULL-terminated string?
   if(value != NULL)
   {
      //Determine the length of the string
      n = osStrlen(value);

      //Check the length of the string
      if(string->value != NULL && string->length == n)
      {
         //Perform string comparison
         if(osStrncmp(string->value, value, n) == 0)
         {
            res = TRUE;
         }
      }
   }

   //Return comparison result
   return res;
}


/**
 * @brief Split a string into tokens
 * @param[in,out] s String to be split
 * @param[in] c Delimiter character
 * @param[out] token Resulting token
 * @return TRUE if a token has been found, else FALSE
 **/

bool_t pemTokenizeString(PemString *s, char_t c, PemString *token)
{
   char_t *p;
   size_t n;
   bool_t found;

   //Search the string for the specified delimiter character
   p = osMemchr(s->value, c, s->length);

   //Delimiter character found?
   if(p != NULL)
   {
      //Retrieve the length of the token
      n = p - s->value;

      //Extract the token from the string
      token->value = s->value;
      token->length = n;

      //Point to the next token
      s->value += n + 1;
      s->length -= n + 1;

      //A token has been found
      found = TRUE;
   }
   else if(s->length > 0)
   {
      //This is the last token
      token->value = s->value;
      token->length = s->length;

      //A token has been found
      found = TRUE;
   }
   else
   {
      //The end of the string has been reached
      found = FALSE;
   }

   //Return TRUE if a token has been found, else FALSE
   return found;
}


/**
 * @brief Removes all leading and trailing whitespace from a string
 * @param[in] s String to be trimmed
 **/

void pemTrimWhitespace(PemString *s)
{
   //Trim whitespace from the beginning
   while(s->length > 0 && osIsspace(s->value[0]))
   {
      s->value++;
      s->length--;
   }

   //Trim whitespace from the end
   while(s->length > 0 && osIsspace(s->value[s->length - 1]))
   {
      s->length--;
   }
}

#endif
