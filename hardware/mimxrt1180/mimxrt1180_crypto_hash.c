/**
 * @file mimxrt1180_crypto_hash.c
 * @brief i.MX RT1180 hash hardware accelerator
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
 * @version 2.5.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "fsl_device_registers.h"
#include "ele_crypto.h"
#include "core/crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto.h"
#include "hardware/mimxrt1180/mimxrt1180_crypto_hash.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (MIMXRT1180_CRYPTO_HASH_SUPPORT == ENABLED)

//ELE hash context
SDK_ALIGN(static ele_hash_ctx_t eleHashContext, 8);
//ELE digest output
SDK_ALIGN(static uint8_t eleDigestOut[64], 8);


#if (SHA224_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-224
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha224Compute(const void *data, size_t length, uint8_t *digest)
{
   uint32_t n;
   status_t status;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Digest the message
   status = ELE_Hash(MU_APPS_S3MUA, data, length, eleDigestOut,
      SHA224_DIGEST_SIZE, &n, kELE_Sha224);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA224_DIGEST_SIZE);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-224 message digest context
 * @param[in] context Pointer to the SHA-224 context to initialize
 **/

void sha224Init(Sha224Context *context)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Initialize hash computation
   ELE_Hash_Init(MU_APPS_S3MUA, &eleHashContext, kELE_Sha224);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Update the SHA-224 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-224 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha224Update(Sha224Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));
   //Digest the message
   ELE_Hash_Update(MU_APPS_S3MUA, &eleHashContext, kELE_Sha224, data, length);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Finish the SHA-224 message digest
 * @param[in] context Pointer to the SHA-224 context
 * @param[out] digest Calculated digest
 **/

void sha224Final(Sha224Context *context, uint8_t *digest)
{
   uint32_t n;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));

   //Finalize hash computation
   ELE_Hash_Finish(MU_APPS_S3MUA, &eleHashContext, kELE_Sha224,
      eleDigestOut, SHA224_DIGEST_SIZE, &n, NULL, 0);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA224_DIGEST_SIZE);
}

#endif
#if (SHA256_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
   uint32_t n;
   status_t status;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Digest the message
   status = ELE_Hash(MU_APPS_S3MUA, data, length, eleDigestOut,
      SHA256_DIGEST_SIZE, &n, kELE_Sha256);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA256_DIGEST_SIZE);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

void sha256Init(Sha256Context *context)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Initialize hash computation
   ELE_Hash_Init(MU_APPS_S3MUA, &eleHashContext, kELE_Sha256);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));
   //Digest the message
   ELE_Hash_Update(MU_APPS_S3MUA, &eleHashContext, kELE_Sha256, data, length);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest
 **/

void sha256Final(Sha256Context *context, uint8_t *digest)
{
   uint32_t n;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));

   //Finalize hash computation
   ELE_Hash_Finish(MU_APPS_S3MUA, &eleHashContext, kELE_Sha256,
      eleDigestOut, SHA256_DIGEST_SIZE, &n, NULL, 0);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA256_DIGEST_SIZE);
}

#endif
#if (SHA384_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-384
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha384Compute(const void *data, size_t length, uint8_t *digest)
{
   uint32_t n;
   status_t status;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Digest the message
   status = ELE_Hash(MU_APPS_S3MUA, data, length, eleDigestOut,
      SHA384_DIGEST_SIZE, &n, kELE_Sha384);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA384_DIGEST_SIZE);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-384 message digest context
 * @param[in] context Pointer to the SHA-384 context to initialize
 **/

void sha384Init(Sha384Context *context)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Initialize hash computation
   ELE_Hash_Init(MU_APPS_S3MUA, &eleHashContext, kELE_Sha384);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Update the SHA-384 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-384 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha384Update(Sha384Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));
   //Digest the message
   ELE_Hash_Update(MU_APPS_S3MUA, &eleHashContext, kELE_Sha384, data, length);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Finish the SHA-384 message digest
 * @param[in] context Pointer to the SHA-384 context
 * @param[out] digest Calculated digest
 **/

void sha384Final(Sha384Context *context, uint8_t *digest)
{
   uint32_t n;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));

   //Finalize hash computation
   ELE_Hash_Finish(MU_APPS_S3MUA, &eleHashContext, kELE_Sha384,
      eleDigestOut, SHA384_DIGEST_SIZE, &n, NULL, 0);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA384_DIGEST_SIZE);
}

#endif
#if (SHA512_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SHA-512
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sha512Compute(const void *data, size_t length, uint8_t *digest)
{
   uint32_t n;
   status_t status;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Digest the message
   status = ELE_Hash(MU_APPS_S3MUA, data, length, eleDigestOut,
      SHA512_DIGEST_SIZE, &n, kELE_Sha512);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA512_DIGEST_SIZE);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SHA-512 message digest context
 * @param[in] context Pointer to the SHA-512 context to initialize
 **/

void sha512Init(Sha512Context *context)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Initialize hash computation
   ELE_Hash_Init(MU_APPS_S3MUA, &eleHashContext, kELE_Sha512);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Update the SHA-512 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-512 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha512Update(Sha512Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));
   //Digest the message
   ELE_Hash_Update(MU_APPS_S3MUA, &eleHashContext, kELE_Sha512, data, length);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Finish the SHA-512 message digest
 * @param[in] context Pointer to the SHA-512 context
 * @param[out] digest Calculated digest
 **/

void sha512Final(Sha512Context *context, uint8_t *digest)
{
   uint32_t n;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));

   //Finalize hash computation
   ELE_Hash_Finish(MU_APPS_S3MUA, &eleHashContext, kELE_Sha512,
      eleDigestOut, SHA512_DIGEST_SIZE, &n, NULL, 0);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SHA512_DIGEST_SIZE);
}

#endif
#if (SM3_SUPPORT == ENABLED)

/**
 * @brief Digest a message using SM3
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t sm3Compute(const void *data, size_t length, uint8_t *digest)
{
   uint32_t n;
   status_t status;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Digest the message
   status = ELE_Hash(MU_APPS_S3MUA, data, length, eleDigestOut,
      SM3_DIGEST_SIZE, &n, kELE_SM3256);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SM3_DIGEST_SIZE);

   //Return status code
   return (status == kStatus_Success) ? NO_ERROR : ERROR_FAILURE;
}


/**
 * @brief Initialize SM3 message digest context
 * @param[in] context Pointer to the SM3 context to initialize
 **/

void sm3Init(Sm3Context *context)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Initialize hash computation
   ELE_Hash_Init(MU_APPS_S3MUA, &eleHashContext, kELE_SM3256);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Update the SM3 context with a portion of the message being hashed
 * @param[in] context Pointer to the SM3 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sm3Update(Sm3Context *context, const void *data, size_t length)
{
   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));
   //Digest the message
   ELE_Hash_Update(MU_APPS_S3MUA, &eleHashContext, kELE_SM3256, data, length);
   //Save hash context
   osMemcpy(&context->eleContext, &eleHashContext, sizeof(ele_hash_ctx_t));

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);
}


/**
 * @brief Finish the SM3 message digest
 * @param[in] context Pointer to the SM3 context
 * @param[out] digest Calculated digest
 **/

void sm3Final(Sm3Context *context, uint8_t *digest)
{
   uint32_t n;

   //Acquire exclusive access to the ELE module
   osAcquireMutex(&mimxrt1180CryptoMutex);

   //Restore hash context
   osMemcpy(&eleHashContext, &context->eleContext, sizeof(ele_hash_ctx_t));

   //Finalize hash computation
   ELE_Hash_Finish(MU_APPS_S3MUA, &eleHashContext, kELE_SM3256,
      eleDigestOut, SM3_DIGEST_SIZE, &n, NULL, 0);

   //Release exclusive access to the ELE module
   osReleaseMutex(&mimxrt1180CryptoMutex);

   //Copy the resulting digest
   osMemcpy(digest, eleDigestOut, SM3_DIGEST_SIZE);
}

#endif
#endif
