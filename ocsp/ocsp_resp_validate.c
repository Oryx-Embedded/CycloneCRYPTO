/**
 * @file ocsp_resp_validate.c
 * @brief OCSP response validation
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
#define TRACE_LEVEL OCSP_TRACE_LEVEL

//Dependencies
#include "ocsp/ocsp_resp_validate.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_validate.h"
#include "pkix/x509_sign_verify.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check crypto library configuration
#if (OCSP_SUPPORT == ENABLED)


/**
 * @brief OCSP response validation
 * @param[in] response Pointer to the OCSP response to be verified
 * @param[in] certInfo End entity certificate
 * @param[in] issuerCertInfo Issuer's certificate
 * @param[in] nonce Pointer to the random nonce (optional parameter)
 * @param[in] nonceLen Length of the nonce, in bytes (optional parameter)
 * @return Error code
 **/

error_t ocspValidateResponse(const OcspResponse *response,
   const X509CertInfo *certInfo, const X509CertInfo *issuerCertInfo,
   const uint8_t *nonce, size_t nonceLen)
{
   error_t error;
   const OcspBasicResponse *basicResponse;
   const OcspSingleResponse *singleResponse;

   //Check parameters
   if(response == NULL || certInfo == NULL || issuerCertInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //In case of errors, the OCSP responder may return an error message. These
   //messages are not signed (refer to RFC 6960, section 2.3)
   if(response->responseStatus != OCSP_RESP_STATUS_SUCCESSFUL)
      return ERROR_UNEXPECTED_RESPONSE;

   //OCSP responders shall be capable of producing responses of the
   //id-pkix-ocsp-basic response type
   if(oidComp(response->responseType.value, response->responseType.length,
      PKIX_OCSP_BASIC_OID, sizeof(PKIX_OCSP_BASIC_OID)))
   {
      return ERROR_INVALID_RESPONSE;
   }

   //Point to the basic response
   basicResponse = &response->basicResponse;

   //The response must include a SingleResponse for each certificate in
   //the request
   if(basicResponse->tbsResponseData.numResponses < 1)
      return ERROR_INVALID_RESPONSE;

   //Point to the response
   singleResponse = &basicResponse->tbsResponseData.responses[0];

   //The OCSP client must confirm that the certificate identified in a received
   //response corresponds to the certificate that was identified in the
   //corresponding request
   error = ocspCheckCertId(&singleResponse->certId, certInfo, issuerCertInfo);
   //Any error to report?
   if(error)
      return error;

   //The OCSP client must confirm that the signature on the response is valid
   error = ocspCheckResponseSignature(basicResponse, issuerCertInfo);
   //Any error to report?
   if(error)
      return error;

   //Check the validity interval of the OCSP response
   error = ocspCheckValidity(singleResponse);
   //Any error to report?
   if(error)
      return error;

   //The Nonce extension is used to cryptographically binds a request and a
   //response to prevent replay attacks (refer to RFC 8954, section 2.1)
   error = ocspCheckNonce(&basicResponse->tbsResponseData.responseExtensions,
      nonce, nonceLen);

   //Return status code
   return error;
}


/**
 * @brief Verify response signature
 * @param[in] basicResponse Pointer to the basic response
 * @param[in] issuerCertInfo Issuer's certificate
 * @return Error code
 **/

error_t ocspCheckResponseSignature(const OcspBasicResponse *basicResponse,
   const X509CertInfo *issuerCertInfo)
{
   error_t error;
   const OcspResponderId *responderId;

   //Point to the ResponderID information
   responderId = &basicResponse->tbsResponseData.responderId;

   //Check the identity of the signer
   error = ocspCheckResponderId(responderId, issuerCertInfo);

   //A certificate's issuer can either sign the OCSP responses itself or
   //explicitly designate this authority to another entity
   if(!error)
   {
      //The value for signature shall be computed on the hash of the DER
      //encoding of ResponseData
      error = x509VerifySignature(&basicResponse->tbsResponseData.raw,
         &basicResponse->signatureAlgo,
         &issuerCertInfo->tbsCert.subjectPublicKeyInfo,
         &basicResponse->signature);
   }
#if (OCSP_SIGN_DELEGATION_SUPPORT == ENABLED)
   else
   {
      size_t length;
      const uint8_t *data;
      Asn1Tag tag;
      X509CertInfo *responderCertInfo;

      //Allocate a memory buffer to store X.509 certificate info
      responderCertInfo = cryptoAllocMem(sizeof(X509CertInfo));

      //Successful memory allocation?
      if(responderCertInfo != NULL)
      {
         //The responder may include certificates in the Certs field of
         //BasicOCSPResponse that help the OCSP client verify the responder's
         //signature (refer to RFC 6960, section 4.2.2.3)
         data = basicResponse->certs.raw.value;
         length = basicResponse->certs.raw.length;

         //Loop through the list of certificates
         while(length > 0)
         {
            //Determine the length of the X.509 certificate
            error = asn1ReadTag(data, length, &tag);

            //Check status code
            if(!error)
            {
               //Parse X.509 certificate
               error = x509ParseCertificate(data, tag.totalLength,
                  responderCertInfo);

               //Check status code
               if(!error)
               {
                  //This certificate must be issued directly to the responder by
                  //the cognizant CA (refer to RFC 6960, section 2.6)
                  error = ocspCheckResponderCert(responderId, responderCertInfo,
                     issuerCertInfo);
               }

               //Check status code
               if(!error)
               {
                  //The value for signature shall be computed on the hash of the
                  //DER encoding of ResponseData
                  error = x509VerifySignature(&basicResponse->tbsResponseData.raw,
                     &basicResponse->signatureAlgo,
                     &responderCertInfo->tbsCert.subjectPublicKeyInfo,
                     &basicResponse->signature);
               }

               //Check status code
               if(!error)
               {
                  //The signature on the response is valid
                  break;
               }

               //Point to the next certificate
               data += tag.totalLength;
               length -= tag.totalLength;
            }
            else
            {
               //The Certs field is malformed
               break;
            }
         }

         //Release previously allocated memory
         cryptoFreeMem(responderCertInfo);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Check responder's certificate
 * @param[in] responderId Pointer to the responder identifier
 * @param[in] responderCertInfo Responder's certificate
 * @param[in] issuerCertInfo Issuer's certificate
 * @return Error code
 **/

error_t ocspCheckResponderCert(const OcspResponderId *responderId,
   const X509CertInfo *responderCertInfo, const X509CertInfo *issuerCertInfo)
{
   error_t error;
   const X509Extensions *extensions;

   //Point to the list of extensions
   extensions = &responderCertInfo->tbsCert.extensions;

   //The ResponderID information must correspond to the certificate that was
   //used to sign the response (refer to RFC 6960, section 4.2.2.3)
   error = ocspCheckResponderId(responderId, responderCertInfo);
   //Any error to report?
   if(error)
      return error;

   //The OCSP signing certificate must contain an extension of type
   //id-pkix-ocsp-nocheck (refer to BR, section 4.9.9)
   if(!extensions->pkixOcspNoCheck.present)
      return ERROR_BAD_CERTIFICATE;

   //OCSP signing delegation shall be designated by the inclusion of
   //id-kp-OCSPSigning in an extended key usage certificate extension included
   //in the OCSP response signer's certificate
   if((extensions->extKeyUsage.bitmap & X509_EXT_KEY_USAGE_OCSP_SIGNING) == 0)
      return ERROR_BAD_CERTIFICATE;

   //The certificate must be issued directly by the CA that is identified in
   //the request (refer to RFC 6960, section 4.2.2.2)
   error = x509ValidateCertificate(responderCertInfo, issuerCertInfo, 0);

   //Return status code
   return error;
}


/**
 * @brief Check responder identifier
 * @param[in] responderId Pointer to the responder identifier
 * @param[in] issuerCertInfo Issuer's certificate
 * @return Error code
 **/

error_t ocspCheckResponderId(const OcspResponderId *responderId,
   const X509CertInfo *issuerCertInfo)
{
   error_t error;
   const X509SubjectPublicKeyInfo *responderPublicKeyInfo;
   uint8_t digest[SHA1_DIGEST_SIZE];

   //Initialize status code
   error = NO_ERROR;

   //The responder ID can be either the name of the responder or a hash of
   //the responder's public key
   if(responderId->keyHash.value != NULL &&
      responderId->keyHash.length > 0)
   {
      //Point to the responder's public key
      responderPublicKeyInfo = &issuerCertInfo->tbsCert.subjectPublicKeyInfo;

      //Compute the SHA-1 hash of responder's public key
      error = sha1Compute(responderPublicKeyInfo->rawSubjectPublicKey.value,
         responderPublicKeyInfo->rawSubjectPublicKey.length, digest);

      //Check status code
      if(!error)
      {
         //The identity of the signer must match the intended recipient of
         //the request
         if(responderId->keyHash.length != SHA1_DIGEST_SIZE ||
            osMemcmp(responderId->keyHash.value, digest, SHA1_DIGEST_SIZE) != 0)
         {
            error = ERROR_WRONG_ISSUER;
         }
      }
   }
   else if(responderId->name.raw.value != NULL &&
      responderId->name.raw.length > 0)
   {
      //The identity of the signer must match the intended recipient of the
      //request
      if(!x509CompareName(responderId->name.raw.value,
         responderId->name.raw.length,
         issuerCertInfo->tbsCert.subject.raw.value,
         issuerCertInfo->tbsCert.subject.raw.length))
      {
         error = ERROR_WRONG_ISSUER;
      }
   }
   else
   {
      //The responder ID is not valid
      error = ERROR_WRONG_ISSUER;
   }

   //Return status code
   return error;
}


/**
 * @brief Check certificate identifier
 * @param[in] certId Pointer to the certificate identifier
 * @param[in] certInfo End entity certificate
 * @param[in] issuerCertInfo Issuer's certificate
 * @return Error code
 **/

error_t ocspCheckCertId(const OcspCertId *certId, const X509CertInfo *certInfo,
   const X509CertInfo *issuerCertInfo)
{
   error_t error;
   const HashAlgo *hashAlgo;
   const X509SubjectPublicKeyInfo *issuerPublicKeyInfo;
   uint8_t digest[MAX_HASH_DIGEST_SIZE];

   //Retrieve the hash algorithm that was used to generate the IssuerNameHash
   //and IssuerKeyHash values
   hashAlgo = ocspGetHashAlgo(certId->hashAlgo.value, certId->hashAlgo.length);
   //Invalid hash algorithm?
   if(hashAlgo == NULL)
      return ERROR_UNSUPPORTED_HASH_ALGO;

   //Compute the hash of the issuer's distinguished name (DN). The hash shall
   //be calculated over the DER encoding of the issuer's name field in the
   //certificate being checked (refer to RFC 6960, section 4.1.1)
   error = hashAlgo->compute(certInfo->tbsCert.issuer.raw.value,
      certInfo->tbsCert.issuer.raw.length, digest);
   //Any error to report?
   if(error)
      return error;

   //Check IssuerNameHash value
   if(certId->issuerNameHash.length != hashAlgo->digestSize ||
      osMemcmp(certId->issuerNameHash.value, digest, hashAlgo->digestSize) != 0)
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the issuer's public key
   issuerPublicKeyInfo = &issuerCertInfo->tbsCert.subjectPublicKeyInfo;

   //Compute the hash of the issuer's public key. The hash shall be calculated
   //over the value (excluding tag and length) of the subject public key field
   //in the issuer's certificate
   error = hashAlgo->compute(issuerPublicKeyInfo->rawSubjectPublicKey.value,
      issuerPublicKeyInfo->rawSubjectPublicKey.length, digest);
   //Any error to report?
   if(error)
      return error;

   //Check IssuerKeyHash value
   if(certId->issuerKeyHash.length != hashAlgo->digestSize ||
      osMemcmp(certId->issuerKeyHash.value, digest, hashAlgo->digestSize) != 0)
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //Check serial number
   if(certId->serialNumber.length != certInfo->tbsCert.serialNumber.length ||
      osMemcmp(certId->serialNumber.value, certInfo->tbsCert.serialNumber.value,
      certInfo->tbsCert.serialNumber.length) != 0)
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //The certificate identified in the OCSP response corresponds to the
   //certificate that was identified in the corresponding request
   return NO_ERROR;
}


/**
 * @brief Check the validity interval of the OCSP response
 * @param[in] singleResponse Pointer to the OCSP response
 * @return Error code
 **/

error_t ocspCheckValidity(const OcspSingleResponse *singleResponse)
{
   error_t error;
   time_t currentTime;
   DateTime currentDate;

   //Initialize status
   error = NO_ERROR;

   //Retrieve current time
   currentTime = getCurrentUnixTime();

   //Any real-time clock implemented?
   if(currentTime != 0)
   {
      //Convert Unix timestamp to date
      convertUnixTimeToDate(currentTime, &currentDate);

      //The time at which the status being indicated is known to be correct
      //must be sufficiently recent
      if(compareDateTime(&currentDate, &singleResponse->thisUpdate) < 0)
      {
         error = ERROR_RESPONSE_EXPIRED;
      }

      //The NextUpdate field is optional
      if(singleResponse->nextUpdate.year != 0)
      {
         //When available, the time at or before which newer information will
         //be available about the status of the certificate must be greater
         //than the current time
         if(compareDateTime(&currentDate, &singleResponse->nextUpdate) > 0)
         {
            error = ERROR_RESPONSE_EXPIRED;
         }
      }
      else
      {
         //If NextUpdate is not set, the responder is indicating that newer
         //revocation information is available all the time
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Check nonce
 * @param[in] extensions Pointer to the OCSP extensions
 * @param[in] nonce Pointer to the random nonce (optional parameter)
 * @param[in] nonceLen Length of the nonce, in bytes (optional parameter)
 * @return Error code
 **/

error_t ocspCheckNonce(const OcspExtensions *extensions, const uint8_t *nonce,
   size_t nonceLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check whether a Nonce extension was sent in the OCSP request
   if(nonce != NULL && nonceLen > 0)
   {
      //Any Nonce extension received in the response?
      if(extensions->nonce.value != NULL && extensions->nonce.length > 0)
      {
         //Ensure the received nonce matches the nonce sent in the request
         if(extensions->nonce.length != nonceLen ||
            osMemcmp(extensions->nonce.value, nonce, nonceLen) != 0)
         {
            return ERROR_WRONG_NONCE;
         }
      }
      else
      {
         //The OCSP responder may choose not to send the Nonce extension in the
         //OCSP response even if the client has sent the Nonce extension in the
         //request (refer to RFC 8954, section 3.1)
         error = ERROR_WRONG_NONCE;
      }
   }
   else
   {
      //The OCSP request does not contain a Nonce extension
   }

   //Return status code
   return error;
}

#endif
