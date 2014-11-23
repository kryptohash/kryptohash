/* 
KeccakRnd.c: Implementation of a simple Pseudo Random Number Generator using the
Keccak sponge function.

Note: this is not a Cryptographically Secure Pseudo Random Number Generator.

Copyright (c) 2014 Chilean Krypto-Miners. 
Distributed under the MIT/X11 software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/

/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to their website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

The following source files were obtained from the KeccakCodePackage in Github:
https://github.com/gvanas/KeccakCodePackage

brg_endian.h
KeccakF-1600-interface.h
KeccakF-1600-reference.c
KeccakF-1600-reference.h
KeccakSponge.c
KeccakSponge.h

*/

#include "KeccakRnd.h"
#include "KeccakSponge.h"
#include <string.h>

/*
    keccakprng_init()
        Initializes structure that contains the PRNG state and pseudo random generated output.

    Input parameters:
        prngStruct: Pointer to the struct location to be initialized.

    Output:
       -1: Invalid input parameter.
       >0: Amount of data in bytes needed to properly seed the PRNG.
*/
int keccakprng_init(PRNG_STRUCT *prngStruct)
{
    /* Sanity check */
    if (prngStruct == NULL) {
        return(-1);
    }

    memset(prngStruct->prngState, 0, sizeof (prngStruct->prngState));
    memset(prngStruct->prngOutput, 0, sizeof (prngStruct->prngOutput));
    prngStruct->prngDataAvailable = 0;
    prngStruct->prngSeedThreshold = PRNG_SEED_THRESHOLD;

    return(prngStruct->prngSeedThreshold);
}

/*
    keccakprng_seed()
        Seeds the PRNG.

    Input parameters:
        prngStruct: Pointer to the struct location to be seeded.
        dataIn:     Seed data to be added to the PRNG state after being squeezed by the keccak sponge.
        dataLen:    How many bytes to be squeezed.

    Output:
         0: Seed completed.
        -1: Invalid input parameters.
        >0: Amount of data in bytes needed to properly seed the PRNG.
*/
int keccakprng_seed(PRNG_STRUCT *prngStruct, const unsigned char *dataIn, unsigned int dataLen)
{
    Keccak_SpongeInstance sponge;
    unsigned char squeeze[PRNG_STATE_SZ];
    unsigned short carry = 0;
    int i;

    /* Sanity checks */
    if (prngStruct == NULL || dataIn == NULL || dataLen == 0) {
        return(-1);
    }

    // Use Keccak sponge Rate and Capacity values for SHA3-224
    Keccak_SpongeInitialize(&sponge, KECCAK_RND_224_R, KECCAK_RND_224_C);
    Keccak_SpongeAbsorb(&sponge, dataIn, dataLen);
    Keccak_SpongeSqueeze(&sponge, squeeze, PRNG_STATE_SZ);

    /* Add new squeeze into current randomStruct->state */
    for (i = 0; i < PRNG_STATE_SZ; i++) {
        carry += prngStruct->prngState[(PRNG_STATE_SZ - 1) - i] + squeeze[(PRNG_STATE_SZ - 1) - i];
        prngStruct->prngState[(PRNG_STATE_SZ - 1) - i] = (unsigned char)carry;
        carry >>= 8;
    }

    if (prngStruct->prngSeedThreshold < dataLen) {
        prngStruct->prngSeedThreshold = 0;
    }
    else {
        prngStruct->prngSeedThreshold -= dataLen;
    }

    /* Clear the locals before exiting. */
    memset(&sponge, 0, sizeof(sponge));
    memset(squeeze, 0, sizeof(squeeze));
    i = 0;
    carry = 0;

    return(prngStruct->prngSeedThreshold);
}

/*
    keccakprng_bytes()
        Puts pseudo-random bytes into a buffer.

    Input parameters:
        rndStruct: Pointer to the struct location of the PRNG.
        dataOut    Pointer to the buffer that will receive the pseudo-random bytes.
        dataLen:   How many pseudo-random bytes to put into the buffer.

    Output:
         0: Success.
        -1: Invalid input parameters.
        -2: Seeding is needed; PRNG was not properly initialized.
*/
int keccakprng_bytes(PRNG_STRUCT *prngStruct, unsigned char *dataOut, unsigned int dataLen)
{
    Keccak_SpongeInstance sponge;
    unsigned int dataAvailable, i;

    /* Sanity checks */
    if (prngStruct == NULL || dataOut == NULL || dataLen == 0) {
        return(-1);
    }

    /* Check if seeding is needed */
    if (prngStruct->prngSeedThreshold) {
        return(-2);
    }

    dataAvailable = prngStruct->prngDataAvailable;

    while (dataLen > dataAvailable) {
        /* Copy prngStruct->prngOutput to data */
        memcpy(dataOut, &prngStruct->prngOutput[PRNG_STATE_SZ - dataAvailable], dataAvailable);
        dataOut += dataAvailable;
        dataLen -= dataAvailable;

        /* Generate new prngStruct->prngOutput */
        Keccak_SpongeInitialize(&sponge, KECCAK_RND_224_R, KECCAK_RND_224_C);
        Keccak_SpongeAbsorb(&sponge, prngStruct->prngState, PRNG_STATE_SZ);
        Keccak_SpongeSqueeze(&sponge, prngStruct->prngOutput, PRNG_STATE_SZ);

        /* Increment prngStruct->prngState */
        for (i = 0; i < PRNG_STATE_SZ; i++) {
            if (prngStruct->prngState[(PRNG_STATE_SZ - 1) - i]++) {
                break;
            }
        }
        dataAvailable = PRNG_STATE_SZ;
    }

    /* Copy randomStruct->output to block */
    memcpy(dataOut, &prngStruct->prngOutput[PRNG_STATE_SZ - dataAvailable], dataLen);
    prngStruct->prngDataAvailable = dataAvailable - dataLen;

    /* Clear the locals before exiting. */
    memset(&sponge, 0, sizeof(sponge));
    i = 0;
    dataAvailable = 0;

    return(0);
}

