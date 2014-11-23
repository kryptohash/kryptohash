// Copyright (c) 2014 Chilean Krypto-Miners. 
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KECCAKPRNG_H
#define KECCAKPRNG_H

#define PRNG_STATE_SZ       28
#define PRNG_SEED_THRESHOLD 40

#define KECCAK_F          1600
#define KECCAK_RND_224_C   448 // Capacity
#define KECCAK_RND_224_R  (KECCAK_F - KECCAK_RND_224_C) // Rate

/*
PRNG structure.
*/
typedef struct
{
    unsigned char prngState[PRNG_STATE_SZ];
    unsigned char prngOutput[PRNG_STATE_SZ];
    unsigned int  prngDataAvailable;
    unsigned int  prngSeedThreshold;
} PRNG_STRUCT;

#if defined (__cplusplus)
extern "C" {
#endif

    extern int keccakprng_init(PRNG_STRUCT *prngStruct);
    extern int keccakprng_seed(PRNG_STRUCT *prngStruct, const unsigned char *dataIn, unsigned int dataLen);
    extern int keccakprng_bytes(PRNG_STRUCT *prngStruct, unsigned char *dataOut, unsigned int dataLen);

#if defined (__cplusplus)
}
#endif

#endif
