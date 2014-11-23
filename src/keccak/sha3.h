// Copyright (c) 2014 Chilean Krypto-Miners. 
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SHA3_H_
#define _SHA3_H_ 1

#include <stddef.h>
#include "KeccakHash.h"

// Keccak parameters for SHA3 as in FIPS 202 draft. **** NOT FINAL YET ****

// SHA3-224
#define SHA3_224_L   224             // Length in bits
#define SHA3_224_DL (SHA3_224_L / 8) // Digest length in bytes

// SHA3-256
#define SHA3_256_L   256             // Length in bits 
#define SHA3_256_DL (SHA3_256_L / 8) // Digest length in bytes

// SHA3-384
#define SHA3_384_L   384             // Length in bits
#define SHA3_384_DL (SHA3_384_L / 8) // Digest length in bytes

// SHA3-512
#define SHA3_512_L   512             // Length in bits
#define SHA3_512_DL (SHA3_512_L / 8) // Digest length in bytes

#define SHAKE_MAX_BITS (128*1024*8)  // 1 Mbits limit

#if defined (__cplusplus)
extern "C" {
#endif

extern unsigned char *SHA3_224(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md);
extern unsigned char *SHA3_256(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md);
extern unsigned char *SHA3_384(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md);
extern unsigned char *SHA3_512(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md);
extern            int SHAKE128(const unsigned char *dataIn, size_t  nBitsIn, unsigned char *md, int nOutBytes);
extern            int SHAKE256(const unsigned char *dataIn, size_t  nBitsIn, unsigned char *md, int nOutBytes);

#if defined (__cplusplus)
}
#endif

#define KECCAK_F 1600

// The below SHA3/SHAKE hash functions are not standardized by the NIST.  Not yet ;-) 

// SHA3_320
#define SHA3_320_P  0x06 // Prefix
#define SHA3_320_L   320 // Length (bits) 
#define SHA3_320_C   640 // Capacity
#define SHA3_320_R  (KECCAK_F - SHA3_320_C) // Rate
#define SHA3_320_DL (SHA3_320_L / 8) // Digest length in bytes

// SHAKE320
#define SHAKE320_P  0x1f // Prefix
#define SHAKE320_C   640 // Capacity
#define SHAKE320_R  (KECCAK_F - SHA3_320_C) // Rate

// SHAKE160
#define SHAKE160_P  0x1F // Prefix
#define SHAKE160_C   320 // Capacity
#define SHAKE160_R  (KECCAK_F - SHAKE160_C) // Rate

// SHAKE80
#define SHAKE80_P  0x1F // Prefix
#define SHAKE80_C   160 // Capacity
#define SHAKE80_R  (KECCAK_F - SHAKE80_C) // Rate

#if defined (__cplusplus)
extern "C" {
#endif

extern unsigned char *SHA3_320(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md);
extern           int   SHAKE80(const unsigned char *dataIn, size_t  nBitsIn, unsigned char *md, int nOutBytes);
extern           int  SHAKE160(const unsigned char *dataIn, size_t  nBitsIn, unsigned char *md, int nOutBytes);
extern           int  SHAKE320(const unsigned char *dataIn, size_t  nBitsIn, unsigned char *md, int nOutBytes);

#if defined (__cplusplus)
}
#endif
#endif

