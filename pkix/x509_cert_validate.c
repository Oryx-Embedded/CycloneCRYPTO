/**
 * @file x509_cert_validate.c
 * @brief X.509 certificate validation
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
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_ext_parse.h"
#include "pkix/x509_cert_validate.h"
#include "pkix/x509_sign_verify.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief X.509 certificate validation
 * @param[in] certInfo X.509 certificate to be verified
 * @param[in] issuerCertInfo Issuer's certificate
 * @param[in] pathLen Certificate path length
 * @return Error code
 **/

error_t x509ValidateCertificate(const X509CertInfo *certInfo,
   const X509CertInfo *issuerCertInfo, uint_t pathLen)
{
   error_t error;
   time_t currentTime;
   const X509Extensions *extensions;

   //Check parameters
   if(certInfo == NULL || issuerCertInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve current time
   currentTime = getCurrentUnixTime();

   //Any real-time clock implemented?
   if(currentTime != 0)
   {
      DateTime currentDate;
      const X509Validity *validity;

      //Convert Unix timestamp to date
      convertUnixTimeToDate(currentTime, &currentDate);

      //The certificate validity period is the time interval during which the
      //CA warrants that it will maintain information about the status of the
      //certificate
      validity = &certInfo->tbsCert.validity;

      //Check the validity period
      if(compareDateTime(&currentDate, &validity->notBefore) < 0 ||
         compareDateTime(&currentDate, &validity->notAfter) > 0)
      {
         //The certificate has expired or is not yet valid
         return ERROR_CERTIFICATE_EXPIRED;
      }
   }

   //Make sure that the subject and issuer names chain correctly
   if(!x509CompareName(certInfo->tbsCert.issuer.raw.value,
      certInfo->tbsCert.issuer.raw.length,
      issuerCertInfo->tbsCert.subject.raw.value,
      issuerCertInfo->tbsCert.subject.raw.length))
   {
      //Report an error
      return ERROR_BAD_CERTIFICATE;
   }

   //Point to the X.509 extensions of the issuer certificate
   extensions = &issuerCertInfo->tbsCert.extensions;

   //X.509 version 3 certificate?
   if(issuerCertInfo->tbsCert.version >= X509_VERSION_3)
   {
      //Ensure that the issuer certificate is a CA certificate
      if(!extensions->basicConstraints.cA)
         return ERROR_BAD_CERTIFICATE;
   }

   //Where pathLenConstraint does not appear, no limit is imposed
   if(extensions->basicConstraints.pathLenConstraint >= 0)
   {
      //The pathLenConstraint field gives the maximum number of non-self-issued
      //intermediate certificates that may follow this certificate in a valid
      //certification path
      if(pathLen > (uint_t) extensions->basicConstraints.pathLenConstraint)
         return ERROR_BAD_CERTIFICATE;
   }

   //Check if the keyUsage extension is present
   if(extensions->keyUsage.bitmap != 0)
   {
      //If the keyUsage extension is present, then the subject public key must
      //not be used to verify signatures on certificates unless the keyCertSign
      //bit is set (refer to RFC 5280, section 4.2.1.3)
      if((extensions->keyUsage.bitmap & X509_KEY_USAGE_KEY_CERT_SIGN) == 0)
         return ERROR_BAD_CERTIFICATE;
   }

   //The ASN.1 DER-encoded tbsCertificate is used as the input to the signature
   //function
   error = x509VerifySignature(&certInfo->tbsCert.raw, &certInfo->signatureAlgo,
      &issuerCertInfo->tbsCert.subjectPublicKeyInfo, &certInfo->signatureValue);

   //Return status code
   return error;
}


/**
 * @brief Check whether the certificate matches the specified FQDN
 * @param[in] certInfo Pointer to the X.509 certificate
 * @param[in] fqdn NULL-terminated string that contains the fully-qualified domain name
 * @return Error code
 **/

error_t x509CheckSubjectName(const X509CertInfo *certInfo,
   const char_t *fqdn)
{
   error_t error;
   bool_t res;
   uint_t i;
   size_t n;
   size_t length;
   const uint8_t *data;
   const X509Extensions *extensions;
   X509GeneralName generalName;

   //Point to the X.509 extensions of the CA certificate
   extensions = &certInfo->tbsCert.extensions;

   //Valid FQDN name provided?
   if(fqdn != NULL)
   {
      //Initialize flag
      res = FALSE;

      //Total number of valid DNS names found in the SubjectAltName extension
      i = 0;

      //Valid SubjectAltName extension?
      if(extensions->subjectAltName.raw.length > 0)
      {
         //The subject alternative name extension allows identities to be bound
         //to the subject of the certificate. These identities may be included
         //in addition to or in place of the identity in the subject field of
         //the certificate
         data = extensions->subjectAltName.raw.value;
         length = extensions->subjectAltName.raw.length;

         //Loop through the list of subject alternative names
         while(!res && length > 0)
         {
            //Parse GeneralName field
            error = x509ParseGeneralName(data, length, &n, &generalName);
            //Failed to decode ASN.1 tag?
            if(error)
               return error;

            //DNS name or IP address?
            if(generalName.type == X509_GENERAL_NAME_TYPE_DNS)
            {
               //Check whether the alternative name matches the specified string
               res = x509CompareSubjectName(generalName.value,
                  generalName.length, fqdn);

               //Increment counter
               i++;
            }
            else if(generalName.type == X509_GENERAL_NAME_TYPE_IP_ADDRESS)
            {
               //Check whether the IP address matches the specified string
               res = x509CompareIpAddr((uint8_t *) generalName.value,
                  generalName.length, fqdn);

               //Increment counter
               i++;
            }
            else
            {
               //Unknown general name type
            }

            //Next item
            data += n;
            length -= n;
         }
      }

      //No match?
      if(!res)
      {
         //The implementation must not seek a match for a reference identifier
         //of CN-ID if the presented identifiers include a DNS-ID, SRV-ID or
         //URI-ID (refer to RFC 6125, section 6.4.4)
         if(i == 0 && certInfo->tbsCert.subject.commonName.length > 0)
         {
            //The implementation may as a last resort check the CN-ID for a match
            res = x509CompareSubjectName(certInfo->tbsCert.subject.commonName.value,
               certInfo->tbsCert.subject.commonName.length, fqdn);
         }
      }

      //Check whether the subject name matches the specified FQDN
      error = res ? NO_ERROR : ERROR_INVALID_NAME;
   }
   else
   {
      //If no valid FQDN name is provided, then the subject name of the
      //certificate is not verified
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Check name constraints
 * @param[in] subjectName Subject name to be verified
 * @param[in] certInfo Pointer to the CA certificate
 * @return Error code
 **/

error_t x509CheckNameConstraints(const char_t *subjectName,
   const X509CertInfo *certInfo)
{
   error_t error;
   bool_t match;
   size_t m;
   size_t n;
   size_t length;
   const uint8_t *data;
   const X509Extensions *extensions;
   X509GeneralName subtree;

   //Initialize status code
   error = NO_ERROR;

   //Point to the X.509 extensions of the CA certificate
   extensions = &certInfo->tbsCert.extensions;

   //Valid subject name provided?
   if(subjectName != NULL)
   {
      //Point to the list of excluded name subtrees
      data = extensions->nameConstraints.excludedSubtrees.value;
      length = extensions->nameConstraints.excludedSubtrees.length;

      //Loop through the names constraints
      while(length > 0)
      {
         //Parse GeneralSubtree field
         error = x509ParseGeneralSubtree(data, length, &n, &subtree);
         //Failed to decode ASN.1 tag?
         if(error)
            break;

         //Initialize flag
         match = FALSE;

         //Check name type
         if(subtree.type == X509_GENERAL_NAME_TYPE_DNS)
         {
            //Check whether the subject name matches the subtree
            match = x509CompareSubtree(subjectName, subtree.value,
               subtree.length);
         }
         else if(subtree.type == X509_GENERAL_NAME_TYPE_DIRECTORY)
         {
            X509Name name;

            //Parse distinguished name
            error = x509ParseName((uint8_t *) subtree.value, subtree.length,
               &m, &name);
            //Failed to decode ASN.1 structure?
            if(error)
               break;

            //Valid common name?
            if(name.commonName.value != NULL)
            {
               //Check whether the subject name matches the subtree
               match = x509CompareSubtree(subjectName, name.commonName.value,
                  name.commonName.length);
            }
         }
         else
         {
            //Just for sanity
         }

         //Any match?
         if(match)
         {
            //The subject name is not acceptable
            error = ERROR_INVALID_NAME;
            break;
         }

         //Next item
         data += n;
         length -= n;
      }

      //Any name matching a restriction in the excludedSubtrees field is
      //invalid regardless of information appearing in the permittedSubtrees
      //(Refer to RFC 5280, section 4.2.1.10)
      if(!error)
      {
         //Point to the list of permitted name subtrees
         data = extensions->nameConstraints.permittedSubtrees.value;
         length = extensions->nameConstraints.permittedSubtrees.length;

         //Loop through the names constraints
         while(length > 0)
         {
            //Parse GeneralSubtree field
            error = x509ParseGeneralSubtree(data, length, &n, &subtree);
            //Failed to decode ASN.1 tag?
            if(error)
               break;

            //Initialize flag
            match = FALSE;

            //Check name type
            if(subtree.type == X509_GENERAL_NAME_TYPE_DNS)
            {
               //Check whether the subject name matches the subtree
               match = x509CompareSubtree(subjectName, subtree.value,
                  subtree.length);
            }
            else if(subtree.type == X509_GENERAL_NAME_TYPE_DIRECTORY)
            {
               X509Name name;

               //Parse distinguished name
               error = x509ParseName((uint8_t *) subtree.value, subtree.length,
                  &m, &name);
               //Failed to decode ASN.1 structure?
               if(error)
                  break;

               //Valid common name?
               if(name.commonName.value != NULL)
               {
                  //Check whether the subject name matches the subtree
                  match = x509CompareSubtree(subjectName, name.commonName.value,
                     name.commonName.length);
               }
            }
            else
            {
               //Just for sanity
            }

            //Any match?
            if(match)
            {
               //The subject name is acceptable
               error = NO_ERROR;
               break;
            }
            else
            {
               //The subject name does not match the current field
               error = ERROR_INVALID_NAME;
            }

            //Next item
            data += n;
            length -= n;
         }
      }
   }
   else
   {
      //If no valid subject name is provided, then the name constraints
      //are not verified
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether the subject name matches the specified FQDN
 * @param[in] subjectName Subject name
 * @param[in] subjectNameLen Length of the subject name
 * @param[in] fqdn NULL-terminated string that contains the fully-qualified domain name
 * @return TRUE if the subject name matches the specified FQDN, else FALSE
 **/

bool_t x509CompareSubjectName(const char_t *subjectName, size_t subjectNameLen,
   const char_t *fqdn)
{
   size_t i;
   size_t j;
   size_t fqdnLen;

   //Retrieve the length of the FQDN
   fqdnLen = osStrlen(fqdn);

   //Initialize variables
   i = 0;
   j = 0;

   //Parse the subject name
   while(i < subjectNameLen && j < fqdnLen)
   {
      //Wildcard name found?
      if(subjectName[i] == '*')
      {
         //The implementation should not attempt to match a presented
         //identifier in which the wildcard character comprises a label other
         //than the left-most label (refer to RFC 6125, section 6.4.3)
         if(i != 0)
         {
            break;
         }

         //The implementation should not compare against anything but the
         //left-most label of the reference identifier
         if(fqdn[j] == '.')
         {
            i++;
         }
         else
         {
            j++;
         }
      }
      else
      {
         //Perform case insensitive character comparison
         if(osTolower(subjectName[i]) != fqdn[j])
         {
            break;
         }

         //Compare next characters
         i++;
         j++;
      }
   }

   //Check whether the subject name matches the specified FQDN
   if(i == subjectNameLen && j == fqdnLen)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Compare a subject name against the specified subtree
 * @param[in] subjectName NULL-terminated string that contains the subject name
 * @param[in] subtree Pointer to the subtree
 * @param[in] subtreeLen Length of the subtree
 * @return Comparison result
 **/

bool_t x509CompareSubtree(const char_t *subjectName, const char_t *subtree,
   size_t subtreeLen)
{
   int_t i;
   int_t j;

   //Point to the last character of the subtree
   i = subtreeLen - 1;
   //Point to the last character of the subject name
   j = osStrlen(subjectName) - 1;

   //Parse the subtree
   while(i >= 0 && j >= 0)
   {
      //Perform case insensitive character comparison
      if(osTolower(subtree[i]) != subjectName[j])
      {
         break;
      }

      //The constraint may specify a host or a domain
      if(subtree[i] == '.' && i == 0)
      {
         //When the constraint begins with a period, it may be expanded with
         //one or more labels (refer to RFC 5280, section 4.2.1.10)
         i = -1;
         j = -1;
      }
      else
      {
         //Compare previous characters
         i--;
         j--;
      }
   }

   //Check whether the subject name matches the specified subtree
   if(i < 0 && j < 0)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Check whether the IP address matches the specified string
 * @param[in] ipAddr Binary representation of the IP address
 * @param[in] ipAddrLen Length of the IP address, in bytes
 * @param[in] str NULL-terminated string representing an IP address
 * @return TRUE if the IP address matches the specified string, else FALSE
 **/

bool_t x509CompareIpAddr(const uint8_t *ipAddr, size_t ipAddrLen,
   const char_t *str)
{
   bool_t res;
   error_t error;
   uint8_t buffer[16];

   //Initialize flag
   res = FALSE;

   //Check the length of the IP address
   if(ipAddrLen == 4)
   {
      //Convert the dot-decimal string to a binary IPv4 address
      error = x509ParseIpv4Addr(str, buffer);

      //Valid IPv4 address?
      if(!error)
      {
         //Compare addresses
         if(osMemcmp(ipAddr, buffer, 4) == 0)
         {
            res = TRUE;
         }
      }
   }
   else if(ipAddrLen == 16)
   {
      //Convert the string representation to a binary IPv6 address
      error = x509ParseIpv6Addr(str, buffer);

      //Valid IPv6 address?
      if(!error)
      {
         //Compare addresses
         if(osMemcmp(ipAddr, buffer, 16) == 0)
         {
            res = TRUE;
         }
      }
   }
   else
   {
      //Invalid IP address
   }

   //Return TRUE if the IP address matches the specified string
   return res;
}


/**
 * @brief Convert a dot-decimal string to a binary IPv4 address
 * @param[in] str NULL-terminated string representing the IPv4 address
 * @param[out] ipAddr Binary representation of the IPv4 address
 * @return Error code
 **/

error_t x509ParseIpv4Addr(const char_t *str, uint8_t *ipAddr)
{
   error_t error;
   int_t i = 0;
   int_t value = -1;

   //Parse input string
   while(1)
   {
      //Decimal digit found?
      if(osIsdigit(*str))
      {
         //First digit to be decoded?
         if(value < 0)
            value = 0;

         //Update the value of the current byte
         value = (value * 10) + (*str - '0');

         //The resulting value shall be in range 0 to 255
         if(value > 255)
         {
            //The conversion failed
            error = ERROR_INVALID_SYNTAX;
            break;
         }
      }
      //Dot separator found?
      else if(*str == '.' && i < 4)
      {
         //Each dot must be preceded by a valid number
         if(value < 0)
         {
            //The conversion failed
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Save the current byte
         ipAddr[i++] = value;
         //Prepare to decode the next byte
         value = -1;
      }
      //End of string detected?
      else if(*str == '\0' && i == 3)
      {
         //The NULL character must be preceded by a valid number
         if(value < 0)
         {
            //The conversion failed
            error = ERROR_INVALID_SYNTAX;
         }
         else
         {
            //Save the last byte of the IPv4 address
            ipAddr[i] = value;
            //The conversion succeeded
            error = NO_ERROR;
         }

         //We are done
         break;
      }
      //Invalid character...
      else
      {
         //The conversion failed
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the next character
      str++;
   }

   //Return status code
   return error;
}


/**
 * @brief Convert a string representation of an IPv6 address to a binary IPv6 address
 * @param[in] str NULL-terminated string representing the IPv6 address
 * @param[out] ipAddr Binary representation of the IPv6 address
 * @return Error code
 **/

error_t x509ParseIpv6Addr(const char_t *str, uint8_t *ipAddr)
{
   error_t error;
   int_t i = 0;
   int_t j = -1;
   int_t k = 0;
   int32_t value = -1;

   //Parse input string
   while(1)
   {
      //Hexadecimal digit found?
      if(isxdigit((uint8_t) *str))
      {
         //First digit to be decoded?
         if(value < 0)
         {
            value = 0;
         }

         //Update the value of the current 16-bit word
         if(osIsdigit(*str))
         {
            value = (value * 16) + (*str - '0');
         }
         else if(osIsupper(*str))
         {
            value = (value * 16) + (*str - 'A' + 10);
         }
         else
         {
            value = (value * 16) + (*str - 'a' + 10);
         }

         //Check resulting value
         if(value > 0xFFFF)
         {
            //The conversion failed
            error = ERROR_INVALID_SYNTAX;
            break;
         }
      }
      //"::" symbol found?
      else if(osStrncmp(str, "::", 2) == 0)
      {
         //The "::" can only appear once in an IPv6 address
         if(j >= 0)
         {
            //The conversion failed
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //The "::" symbol is preceded by a number?
         if(value >= 0)
         {
            //Save the current 16-bit word
            STORE16BE(value, ipAddr + 2 * i);
            i++;

            //Prepare to decode the next 16-bit word
            value = -1;
         }

         //Save the position of the "::" symbol
         j = i;
         //Point to the next character
         str++;
      }
      //":" symbol found?
      else if(*str == ':' && i < 8)
      {
         //Each ":" must be preceded by a valid number
         if(value < 0)
         {
            //The conversion failed
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Save the current 16-bit word
         STORE16BE(value, ipAddr + 2 * i);
         i++;

         //Prepare to decode the next 16-bit word
         value = -1;
      }
      //End of string detected?
      else if(*str == '\0' && i == 7 && j < 0)
      {
         //The NULL character must be preceded by a valid number
         if(value < 0)
         {
            //The conversion failed
            error = ERROR_INVALID_SYNTAX;
         }
         else
         {
            //Save the last 16-bit word of the IPv6 address
            STORE16BE(value, ipAddr + 2 * i);
            //The conversion succeeded
            error = NO_ERROR;
         }

         //We are done
         break;
      }
      else if(*str == '\0' && i < 7 && j >= 0)
      {
         //Save the last 16-bit word of the IPv6 address
         if(value >= 0)
         {
            STORE16BE(value, ipAddr + 2 * i);
            i++;
         }

         //Move the part of the address that follows the "::" symbol
         for(k = 0; k < (i - j); k++)
         {
            value = LOAD16BE(ipAddr + 2 * (i - 1 - k));
            STORE16BE(value, ipAddr + 2 * (7 - k));
         }

         //A sequence of zeroes can now be written in place of "::"
         for(k = 0; k < (8 - i); k++)
         {
            STORE16BE(0, ipAddr + 2 * (j + k));
         }

         //The conversion succeeded
         error = NO_ERROR;
         break;
      }
      //Invalid character...
      else
      {
         //The conversion failed
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the next character
      str++;
   }

   //Return status code
   return error;
}

#endif
