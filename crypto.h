/**
 * @file crypto.h
 * @brief General definitions for cryptographic algorithms
 *
 * @section License
 *
 * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
 * @version 1.7.6
 **/

#ifndef _CRYPTO_H
#define _CRYPTO_H

//Dependencies
#include "os_port.h"
#include "crypto_config.h"
#include "cpu_endian.h"
#include "error.h"

//Multiple precision integer support
#ifndef MPI_SUPPORT
   #define MPI_SUPPORT ENABLED
#elif (MPI_SUPPORT != ENABLED && MPI_SUPPORT != DISABLED)
   #error MPI_SUPPORT parameter is not valid
#endif

//Assembly optimizations for time-critical routines
#ifndef MPI_ASM_SUPPORT
   #define MPI_ASM_SUPPORT DISABLED
#elif (MPI_ASM_SUPPORT != ENABLED && MPI_ASM_SUPPORT != DISABLED)
   #error MPI_ASM_SUPPORT parameter is not valid
#endif

//Base64 encoding support
#ifndef BASE64_SUPPORT
   #define BASE64_SUPPORT ENABLED
#elif (BASE64_SUPPORT != ENABLED && BASE64_SUPPORT != DISABLED)
   #error BASE64_SUPPORT parameter is not valid
#endif

//MD2 hash support
#ifndef MD2_SUPPORT
   #define MD2_SUPPORT ENABLED
#elif (MD2_SUPPORT != ENABLED && MD2_SUPPORT != DISABLED)
   #error MD2_SUPPORT parameter is not valid
#endif

//MD4 hash support
#ifndef MD4_SUPPORT
   #define MD4_SUPPORT ENABLED
#elif (MD4_SUPPORT != ENABLED && MD4_SUPPORT != DISABLED)
   #error MD4_SUPPORT parameter is not valid
#endif

//MD5 hash support
#ifndef MD5_SUPPORT
   #define MD5_SUPPORT ENABLED
#elif (MD5_SUPPORT != ENABLED && MD5_SUPPORT != DISABLED)
   #error MD5_SUPPORT parameter is not valid
#endif

//RIPEMD-128 hash support
#ifndef RIPEMD128_SUPPORT
   #define RIPEMD128_SUPPORT ENABLED
#elif (RIPEMD128_SUPPORT != ENABLED && RIPEMD128_SUPPORT != DISABLED)
   #error RIPEMD128_SUPPORT parameter is not valid
#endif

//RIPEMD-160 hash support
#ifndef RIPEMD160_SUPPORT
   #define RIPEMD160_SUPPORT ENABLED
#elif (RIPEMD160_SUPPORT != ENABLED && RIPEMD160_SUPPORT != DISABLED)
   #error RIPEMD160_SUPPORT parameter is not valid
#endif

//SHA-1 hash support
#ifndef SHA1_SUPPORT
   #define SHA1_SUPPORT ENABLED
#elif (SHA1_SUPPORT != ENABLED && SHA1_SUPPORT != DISABLED)
   #error SHA1_SUPPORT parameter is not valid
#endif

//SHA-224 hash support
#ifndef SHA224_SUPPORT
   #define SHA224_SUPPORT ENABLED
#elif (SHA224_SUPPORT != ENABLED && SHA224_SUPPORT != DISABLED)
   #error SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef SHA256_SUPPORT
   #define SHA256_SUPPORT ENABLED
#elif (SHA256_SUPPORT != ENABLED && SHA256_SUPPORT != DISABLED)
   #error SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef SHA384_SUPPORT
   #define SHA384_SUPPORT ENABLED
#elif (SHA384_SUPPORT != ENABLED && SHA384_SUPPORT != DISABLED)
   #error SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef SHA512_SUPPORT
   #define SHA512_SUPPORT ENABLED
#elif (SHA512_SUPPORT != ENABLED && SHA512_SUPPORT != DISABLED)
   #error SHA512_SUPPORT parameter is not valid
#endif

//SHA-512/224 hash support
#ifndef SHA512_224_SUPPORT
   #define SHA512_224_SUPPORT ENABLED
#elif (SHA512_224_SUPPORT != ENABLED && SHA512_224_SUPPORT != DISABLED)
   #error SHA512_224_SUPPORT parameter is not valid
#endif

//SHA-512/256 hash support
#ifndef SHA512_256_SUPPORT
   #define SHA512_256_SUPPORT ENABLED
#elif (SHA512_256_SUPPORT != ENABLED && SHA512_256_SUPPORT != DISABLED)
   #error SHA512_256_SUPPORT parameter is not valid
#endif

//SHA3-224 hash support
#ifndef SHA3_224_SUPPORT
   #define SHA3_224_SUPPORT DISABLED
#elif (SHA3_224_SUPPORT != ENABLED && SHA3_224_SUPPORT != DISABLED)
   #error SHA3_224_SUPPORT parameter is not valid
#endif

//SHA3-256 hash support
#ifndef SHA3_256_SUPPORT
   #define SHA3_256_SUPPORT DISABLED
#elif (SHA3_256_SUPPORT != ENABLED && SHA3_256_SUPPORT != DISABLED)
   #error SHA3_256_SUPPORT parameter is not valid
#endif

//SHA3-384 hash support
#ifndef SHA3_384_SUPPORT
   #define SHA3_384_SUPPORT DISABLED
#elif (SHA3_384_SUPPORT != ENABLED && SHA3_384_SUPPORT != DISABLED)
   #error SHA3_384_SUPPORT parameter is not valid
#endif

//SHA3-512 hash support
#ifndef SHA3_512_SUPPORT
   #define SHA3_512_SUPPORT DISABLED
#elif (SHA3_512_SUPPORT != ENABLED && SHA3_512_SUPPORT != DISABLED)
   #error SHA3_512_SUPPORT parameter is not valid
#endif

//Keccak support
#ifndef KECCAK_SUPPORT
   #define KECCAK_SUPPORT DISABLED
#elif (KECCAK_SUPPORT != ENABLED && KECCAK_SUPPORT != DISABLED)
   #error KECCAK_SUPPORT parameter is not valid
#endif

//Tiger hash support
#ifndef TIGER_SUPPORT
   #define TIGER_SUPPORT ENABLED
#elif (TIGER_SUPPORT != ENABLED && TIGER_SUPPORT != DISABLED)
   #error TIGER_SUPPORT parameter is not valid
#endif

//Whirlpool hash support
#ifndef WHIRLPOOL_SUPPORT
   #define WHIRLPOOL_SUPPORT ENABLED
#elif (WHIRLPOOL_SUPPORT != ENABLED && WHIRLPOOL_SUPPORT != DISABLED)
   #error WHIRLPOOL_SUPPORT parameter is not valid
#endif

//HMAC support
#ifndef HMAC_SUPPORT
   #define HMAC_SUPPORT ENABLED
#elif (HMAC_SUPPORT != ENABLED && HMAC_SUPPORT != DISABLED)
   #error HMAC_SUPPORT parameter is not valid
#endif

//RC4 encryption support
#ifndef RC4_SUPPORT
   #define RC4_SUPPORT ENABLED
#elif (RC4_SUPPORT != ENABLED && RC4_SUPPORT != DISABLED)
   #error RC4_SUPPORT parameter is not valid
#endif

//RC6 encryption support
#ifndef RC6_SUPPORT
   #define RC6_SUPPORT ENABLED
#elif (RC6_SUPPORT != ENABLED && RC6_SUPPORT != DISABLED)
   #error RC6_SUPPORT parameter is not valid
#endif

//IDEA encryption support
#ifndef IDEA_SUPPORT
   #define IDEA_SUPPORT ENABLED
#elif (IDEA_SUPPORT != ENABLED && IDEA_SUPPORT != DISABLED)
   #error IDEA_SUPPORT parameter is not valid
#endif

//DES encryption support
#ifndef DES_SUPPORT
   #define DES_SUPPORT ENABLED
#elif (DES_SUPPORT != ENABLED && DES_SUPPORT != DISABLED)
   #error DES_SUPPORT parameter is not valid
#endif

//Triple DES encryption support
#ifndef DES3_SUPPORT
   #define DES3_SUPPORT ENABLED
#elif (DES3_SUPPORT != ENABLED && DES3_SUPPORT != DISABLED)
   #error DES3_SUPPORT parameter is not valid
#endif

//AES encryption support
#ifndef AES_SUPPORT
   #define AES_SUPPORT ENABLED
#elif (AES_SUPPORT != ENABLED && AES_SUPPORT != DISABLED)
   #error AES_SUPPORT parameter is not valid
#endif

//Camellia encryption support
#ifndef CAMELLIA_SUPPORT
   #define CAMELLIA_SUPPORT ENABLED
#elif (CAMELLIA_SUPPORT != ENABLED && CAMELLIA_SUPPORT != DISABLED)
   #error CAMELLIA_SUPPORT parameter is not valid
#endif

//SEED encryption support
#ifndef SEED_SUPPORT
   #define SEED_SUPPORT ENABLED
#elif (SEED_SUPPORT != ENABLED && SEED_SUPPORT != DISABLED)
   #error SEED_SUPPORT parameter is not valid
#endif

//ARIA encryption support
#ifndef ARIA_SUPPORT
   #define ARIA_SUPPORT ENABLED
#elif (ARIA_SUPPORT != ENABLED && ARIA_SUPPORT != DISABLED)
   #error ARIA_SUPPORT parameter is not valid
#endif

//ECB mode support
#ifndef ECB_SUPPORT
   #define ECB_SUPPORT ENABLED
#elif (ECB_SUPPORT != ENABLED && ECB_SUPPORT != DISABLED)
   #error ECB_SUPPORT parameter is not valid
#endif

//CBC mode support
#ifndef CBC_SUPPORT
   #define CBC_SUPPORT ENABLED
#elif (CBC_SUPPORT != ENABLED && CBC_SUPPORT != DISABLED)
   #error CBC_SUPPORT parameter is not valid
#endif

//CFB mode support
#ifndef CFB_SUPPORT
   #define CFB_SUPPORT ENABLED
#elif (CFB_SUPPORT != ENABLED && CFB_SUPPORT != DISABLED)
   #error CFB_SUPPORT parameter is not valid
#endif

//OFB mode support
#ifndef OFB_SUPPORT
   #define OFB_SUPPORT ENABLED
#elif (OFB_SUPPORT != ENABLED && OFB_SUPPORT != DISABLED)
   #error OFB_SUPPORT parameter is not valid
#endif

//CTR mode support
#ifndef CTR_SUPPORT
   #define CTR_SUPPORT ENABLED
#elif (CTR_SUPPORT != ENABLED && CTR_SUPPORT != DISABLED)
   #error CTR_SUPPORT parameter is not valid
#endif

//CCM mode support
#ifndef CCM_SUPPORT
   #define CCM_SUPPORT ENABLED
#elif (CCM_SUPPORT != ENABLED && CCM_SUPPORT != DISABLED)
   #error CCM_SUPPORT parameter is not valid
#endif

//GCM mode support
#ifndef GCM_SUPPORT
   #define GCM_SUPPORT ENABLED
#elif (GCM_SUPPORT != ENABLED && GCM_SUPPORT != DISABLED)
   #error GCM_SUPPORT parameter is not valid
#endif

//Chacha support
#ifndef CHACHA_SUPPORT
   #define CHACHA_SUPPORT DISABLED
#elif (CHACHA_SUPPORT != ENABLED && CHACHA_SUPPORT != DISABLED)
   #error CHACHA_SUPPORT parameter is not valid
#endif

//Poly1305 support
#ifndef POLY1305_SUPPORT
   #define POLY1305_SUPPORT DISABLED
#elif (POLY1305_SUPPORT != ENABLED && POLY1305_SUPPORT != DISABLED)
   #error POLY1305_SUPPORT parameter is not valid
#endif

//Chacha20Poly1305 support
#ifndef CHACHA20_POLY1305_SUPPORT
   #define CHACHA20_POLY1305_SUPPORT DISABLED
#elif (CHACHA20_POLY1305_SUPPORT != ENABLED && CHACHA20_POLY1305_SUPPORT != DISABLED)
   #error CHACHA20_POLY1305_SUPPORT parameter is not valid
#endif

//Diffie-Hellman support
#ifndef DH_SUPPORT
   #define DH_SUPPORT ENABLED
#elif (DH_SUPPORT != ENABLED && DH_SUPPORT != DISABLED)
   #error DH_SUPPORT parameter is not valid
#endif

//RSA support
#ifndef RSA_SUPPORT
   #define RSA_SUPPORT ENABLED
#elif (RSA_SUPPORT != ENABLED && RSA_SUPPORT != DISABLED)
   #error RSA_SUPPORT parameter is not valid
#endif

//DSA support
#ifndef DSA_SUPPORT
   #define DSA_SUPPORT ENABLED
#elif (DSA_SUPPORT != ENABLED && DSA_SUPPORT != DISABLED)
   #error DSA_SUPPORT parameter is not valid
#endif

//Elliptic curve cryptography support
#ifndef EC_SUPPORT
   #define EC_SUPPORT ENABLED
#elif (EC_SUPPORT != ENABLED && EC_SUPPORT != DISABLED)
   #error EC_SUPPORT parameter is not valid
#endif

//ECDH support
#ifndef ECDH_SUPPORT
   #define ECDH_SUPPORT ENABLED
#elif (ECDH_SUPPORT != ENABLED && ECDH_SUPPORT != DISABLED)
   #error ECDH_SUPPORT parameter is not valid
#endif

//ECDSA support
#ifndef ECDSA_SUPPORT
   #define ECDSA_SUPPORT ENABLED
#elif (ECDSA_SUPPORT != ENABLED && ECDSA_SUPPORT != DISABLED)
   #error ECDSA_SUPPORT parameter is not valid
#endif

//PKCS #5 support
#ifndef PKCS5_SUPPORT
   #define PKCS5_SUPPORT ENABLED
#elif (PKCS5_SUPPORT != ENABLED && PKCS5_SUPPORT != DISABLED)
   #error PKCS5_SUPPORT parameter is not valid
#endif

//Yarrow PRNG support
#ifndef YARROW_SUPPORT
   #define YARROW_SUPPORT ENABLED
#elif (YARROW_SUPPORT != ENABLED && YARROW_SUPPORT != DISABLED)
   #error YARROW_SUPPORT parameter is not valid
#endif

//Object identifier support
#ifndef OID_SUPPORT
   #define OID_SUPPORT ENABLED
#elif (OID_SUPPORT != ENABLED && OID_SUPPORT != DISABLED)
   #error OID_SUPPORT parameter is not valid
#endif

//ASN.1 syntax support
#ifndef ASN1_SUPPORT
   #define ASN1_SUPPORT ENABLED
#elif (ASN1_SUPPORT != ENABLED && ASN1_SUPPORT != DISABLED)
   #error ASN1_SUPPORT parameter is not valid
#endif

//PEM file support
#ifndef PEM_SUPPORT
   #define PEM_SUPPORT ENABLED
#elif (PEM_SUPPORT != ENABLED && PEM_SUPPORT != DISABLED)
   #error PEM_SUPPORT parameter is not valid
#endif

//X.509 certificate support
#ifndef X509_SUPPORT
   #define X509_SUPPORT ENABLED
#elif (X509_SUPPORT != ENABLED && X509_SUPPORT != DISABLED)
   #error X509_SUPPORT parameter is not valid
#endif

//Memory allocation
#ifndef cryptoAllocMem
   #define cryptoAllocMem(size) osAllocMem(size)
#endif

//Memory deallocation
#ifndef cryptoFreeMem
   #define cryptoFreeMem(p) osFreeMem(p)
#endif

//Maximum context size (hash algorithms)
#if (SHA3_512_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha3_512Context)
#elif (SHA3_384_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha3_384Context)
#elif (SHA3_256_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha3_256Context)
#elif (SHA3_224_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha3_224Context)
#elif (WHIRLPOOL_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(WhirlpoolContext)
#elif (SHA512_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha512Context)
#elif (SHA384_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha384Context)
#elif (SHA512_256_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha512_256Context)
#elif (SHA512_224_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha512_224Context)
#elif (SHA256_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha256Context)
#elif (SHA224_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha224Context)
#elif (TIGER_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(TigerContext)
#elif (SHA1_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Sha1Context)
#elif (RIPEMD160_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Ripemd160Context)
#elif (RIPEMD128_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Ripemd128Context)
#elif (MD5_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Md5Context)
#elif (MD4_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Md4Context)
#elif (MD2_SUPPORT == ENABLED)
   #define MAX_HASH_CONTEXT_SIZE sizeof(Md2Context)
#endif

//Maximum block size (hash algorithms)
#if (SHA3_224_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_224_BLOCK_SIZE
#elif (SHA3_256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_256_BLOCK_SIZE
#elif (SHA512_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA512_BLOCK_SIZE
#elif (SHA384_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA384_BLOCK_SIZE
#elif (SHA512_256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA512_256_BLOCK_SIZE
#elif (SHA512_224_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA512_224_BLOCK_SIZE
#elif (SHA3_384_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_384_BLOCK_SIZE
#elif (SHA3_512_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA3_512_BLOCK_SIZE
#elif (SHA256_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA256_BLOCK_SIZE
#elif (SHA224_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA224_BLOCK_SIZE
#elif (SHA1_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE SHA1_BLOCK_SIZE
#elif (WHIRLPOOL_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE WHIRLPOOL_BLOCK_SIZE
#elif (TIGER_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE TIGER_BLOCK_SIZE
#elif (RIPEMD160_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE RIPEMD160_BLOCK_SIZE
#elif (RIPEMD128_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE RIPEMD128_BLOCK_SIZE
#elif (MD5_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE MD5_BLOCK_SIZE
#elif (MD4_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE MD4_BLOCK_SIZE
#elif (MD2_SUPPORT == ENABLED)
   #define MAX_HASH_BLOCK_SIZE MD2_BLOCK_SIZE
#endif

//Maximum digest size (hash algorithms)
#if (WHIRLPOOL_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE WHIRLPOOL_DIGEST_SIZE
#elif (SHA3_512_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_512_DIGEST_SIZE
#elif (SHA512_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA512_DIGEST_SIZE
#elif (SHA3_384_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_384_DIGEST_SIZE
#elif (SHA384_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA384_DIGEST_SIZE
#elif (SHA3_256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_256_DIGEST_SIZE
#elif (SHA512_256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA512_256_DIGEST_SIZE
#elif (SHA256_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif (SHA3_224_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA3_224_DIGEST_SIZE
#elif (SHA512_224_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA512_224_DIGEST_SIZE
#elif (SHA224_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA224_DIGEST_SIZE
#elif (TIGER_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE TIGER_DIGEST_SIZE
#elif (SHA1_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE SHA1_DIGEST_SIZE
#elif (RIPEMD160_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE RIPEMD160_DIGEST_SIZE
#elif (RIPEMD128_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE RIPEMD128_DIGEST_SIZE
#elif (MD5_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE MD5_DIGEST_SIZE
#elif (MD4_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE MD4_DIGEST_SIZE
#elif (MD2_SUPPORT == ENABLED)
   #define MAX_HASH_DIGEST_SIZE MD2_DIGEST_SIZE
#endif

//Maximum context size (cipher algorithms)
#if (ARIA_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(AriaContext)
#elif (AES_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(AesContext)
#elif (DES3_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(Des3Context)
#elif (CAMELLIA_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(CamelliaContext)
#elif (RC4_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(Rc4Context)
#elif (RC6_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(Rc6Context)
#elif (IDEA_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(IdeaContext)
#elif (DES_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(DesContext)
#elif (SEED_SUPPORT == ENABLED)
   #define MAX_CIPHER_CONTEXT_SIZE sizeof(SeedContext)
#endif

//Maximum block size (cipher algorithms)
#if (CAMELLIA_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE CAMELLIA_BLOCK_SIZE
#elif (AES_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE AES_BLOCK_SIZE
#elif (ARIA_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE ARIA_BLOCK_SIZE
#elif (SEED_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE SEED_BLOCK_SIZE
#elif (RC6_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE RC6_BLOCK_SIZE
#elif (DES3_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE DES3_BLOCK_SIZE
#elif (DES_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE DES_BLOCK_SIZE
#elif (IDEA_SUPPORT == ENABLED)
   #define MAX_CIPHER_BLOCK_SIZE IDEA_BLOCK_SIZE
#endif

//Rotate left operation
#define ROL8(a, n) (((a) << (n)) | ((a) >> (8 - (n))))
#define ROL16(a, n) (((a) << (n)) | ((a) >> (16 - (n))))
#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define ROL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

//Rotate right operation
#define ROR8(a, n) (((a) >> (n)) | ((a) << (8 - (n))))
#define ROR16(a, n) (((a) >> (n)) | ((a) << (16 - (n))))
#define ROR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))
#define ROR64(a, n) (((a) >> (n)) | ((a) << (64 - (n))))

//Shift left operation
#define SHL8(a, n) ((a) << (n))
#define SHL16(a, n) ((a) << (n))
#define SHL32(a, n) ((a) << (n))
#define SHL64(a, n) ((a) << (n))

//Shift right operation
#define SHR8(a, n) ((a) >> (n))
#define SHR16(a, n) ((a) >> (n))
#define SHR32(a, n) ((a) >> (n))
#define SHR64(a, n) ((a) >> (n))


/**
 * @brief Encryption algorithm type
 **/

typedef enum
{
   CIPHER_ALGO_TYPE_STREAM = 0,
   CIPHER_ALGO_TYPE_BLOCK  = 1
} CipherAlgoType;


/**
 * @brief Cipher operation modes
 **/

typedef enum
{
   CIPHER_MODE_NULL              = 0,
   CIPHER_MODE_STREAM            = 1,
   CIPHER_MODE_ECB               = 2,
   CIPHER_MODE_CBC               = 3,
   CIPHER_MODE_CFB               = 4,
   CIPHER_MODE_OFB               = 5,
   CIPHER_MODE_CTR               = 6,
   CIPHER_MODE_CCM               = 7,
   CIPHER_MODE_GCM               = 8,
   CIPHER_MODE_CHACHA20_POLY1305 = 9,
} CipherMode;


//Common API for hash algorithms
typedef error_t (*HashAlgoCompute)(const void *data, size_t length, uint8_t *digest);
typedef void (*HashAlgoInit)(void *context);
typedef void (*HashAlgoUpdate)(void *context, const void *data, size_t length);
typedef void (*HashAlgoFinal)(void *context, uint8_t *digest);

//Common API for encryption algorithms
typedef error_t (*CipherAlgoInit)(void *context, const uint8_t *key, size_t keyLength);
typedef void (*CipherAlgoEncryptStream)(void *context, const uint8_t *input, uint8_t *output, size_t length);
typedef void (*CipherAlgoDecryptStream)(void *context, const uint8_t *input, uint8_t *output, size_t length);
typedef void (*CipherAlgoEncryptBlock)(void *context, const uint8_t *input, uint8_t *output);
typedef void (*CipherAlgoDecryptBlock)(void *context, const uint8_t *input, uint8_t *output);

//Common API for pseudo-random number generators
typedef error_t (*PrngAlgoInit)(void *context);
typedef void (*PrngAlgoRelease)(void *context);
typedef error_t (*PrngAlgoSeed)(void *context, const uint8_t *input, size_t length);
typedef error_t (*PrngAlgoAddEntropy)(void *context, uint_t source, const uint8_t *input, size_t length, size_t entropy);
typedef error_t (*PrngAlgoRead)(void *context, uint8_t *output, size_t length);


/**
 * @brief Generic hash algorithm context
 **/

typedef struct
{
   uint8_t digest[1];
} HashContext;


/**
 * @brief Common interface for hash algorithms
 **/

typedef struct
{
   const char_t *name;
   const uint8_t *oid;
   size_t oidSize;
   size_t contextSize;
   size_t blockSize;
   size_t digestSize;
   HashAlgoCompute compute;
   HashAlgoInit init;
   HashAlgoUpdate update;
   HashAlgoFinal final;
} HashAlgo;


/**
 * @brief Common interface for encryption algorithms
 **/

typedef struct
{
   const char_t *name;
   size_t contextSize;
   CipherAlgoType type;
   size_t blockSize;
   CipherAlgoInit init;
   CipherAlgoEncryptStream encryptStream;
   CipherAlgoDecryptStream decryptStream;
   CipherAlgoEncryptBlock encryptBlock;
   CipherAlgoDecryptBlock decryptBlock;
} CipherAlgo;


/**
 * @brief Common interface for pseudo-random number generators
 **/

typedef struct
{
   const char_t *name;
   size_t contextSize;
   PrngAlgoInit init;
   PrngAlgoRelease release;
   PrngAlgoSeed seed;
   PrngAlgoAddEntropy addEntropy;
   PrngAlgoRead read;
} PrngAlgo;

#endif
