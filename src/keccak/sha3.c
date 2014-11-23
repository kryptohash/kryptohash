/*
sha3.c: Implementation of the SHA3/SHAKE hashing function using
the Keccak Sponge function selected by NIST to be SHA3. 
**** NOTE: THESE PARAMETERS ARE STILL DRAFT AND NOT YET FINAL *****
Code written by Oscar A. Perez

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
KeccakHash.c
KeccakHash.h
KeccakSponge.c
KeccakSponge.h

*/

#include "sha3.h"
#include <string.h>

unsigned char *SHA3_224(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md)
{
    Keccak_HashInstance h;
    static BitSequence  m[SHA3_224_DL];

    if (md == NULL) {
        md = m;
    }
    Keccak_HashInitialize_SHA3_224(&h);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBytesIn * 8);
    Keccak_HashFinal(&h, md);

    return(md);
}

unsigned char *SHA3_256(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md)
{
    Keccak_HashInstance h;
    static BitSequence  m[SHA3_256_DL];

    if (md == NULL) {
        md = m;
    }
    Keccak_HashInitialize_SHA3_256(&h);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBytesIn * 8);
    Keccak_HashFinal(&h, md);

    return(md);
}

unsigned char *SHA3_384(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md)
{
    Keccak_HashInstance h;
    static BitSequence  m[SHA3_384_DL];

    if (md == NULL) {
        md = m;
    }
    Keccak_HashInitialize_SHA3_384(&h);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBytesIn * 8);
    Keccak_HashFinal(&h, md);

    return(md);
}

unsigned char *SHA3_512(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md)
{
    Keccak_HashInstance h;
    static BitSequence  m[SHA3_512_DL];

    if (md == NULL) {
        md = m;
    }
    Keccak_HashInitialize_SHA3_512(&h);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBytesIn * 8);
    Keccak_HashFinal(&h, md);

    return(md);
}


int SHAKE128(const unsigned char *dataIn, size_t nBitsIn, unsigned char *md, int nOutBytes)
{
    Keccak_HashInstance h;

    if (md == NULL || nOutBytes == 0) {
        return 0;
    }
    if (nOutBytes > SHAKE_MAX_BITS / 8) {
        nOutBytes = SHAKE_MAX_BITS / 8;
    }
    Keccak_HashInitialize_SHAKE128(&h);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBitsIn);
    Keccak_HashFinal(&h, NULL);
    Keccak_HashSqueeze(&h, md, nOutBytes * 8);

    return nOutBytes;
}

int SHAKE256(const unsigned char *dataIn, size_t nBitsIn, unsigned char *md, int nOutBytes)
{
    Keccak_HashInstance h;

    if (md == NULL || nOutBytes == 0) {
        return 0;
    }
    if (nOutBytes > SHAKE_MAX_BITS / 8) {
        nOutBytes = SHAKE_MAX_BITS / 8;
    }
    Keccak_HashInitialize_SHAKE256(&h);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBitsIn);
    Keccak_HashFinal(&h, NULL);
    Keccak_HashSqueeze(&h, md, nOutBytes * 8);

    return nOutBytes;
}


// The below SHA3/SHAKE hash functions are not standardized by the NIST.  Not yet ;-) 

unsigned char *SHA3_320(const unsigned char *dataIn, size_t nBytesIn, unsigned char *md)
{
    Keccak_HashInstance h;
    static BitSequence  m[SHA3_320_DL];

    if (md == NULL) {
        md = m;
    }
    Keccak_HashInitialize(&h, SHA3_320_R, SHA3_320_C, SHA3_320_L, SHA3_320_P);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBytesIn * 8);
    Keccak_HashFinal(&h, md);

    return(md);
}

int SHAKE320(const unsigned char *dataIn, size_t nBitsIn, unsigned char *md, int nOutBytes)
{
    Keccak_HashInstance h;

    if (md == NULL || nOutBytes == 0) {
        return 0;
    }
    if (nOutBytes > SHAKE_MAX_BITS / 8) {
        nOutBytes = SHAKE_MAX_BITS / 8;
    }
    Keccak_HashInitialize(&h, SHAKE320_R, SHAKE320_C, 0, SHAKE320_P);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBitsIn);
    Keccak_HashFinal(&h, NULL);
    Keccak_HashSqueeze(&h, md, nOutBytes * 8);

    return nOutBytes;
}

int SHAKE160(const unsigned char *dataIn, size_t nBitsIn, unsigned char *md, int nOutBytes)
{
    Keccak_HashInstance h;

    if (md == NULL || nOutBytes == 0) {
        return 0;
    }
    if (nOutBytes > SHAKE_MAX_BITS / 8) {
        nOutBytes = SHAKE_MAX_BITS / 8;
    }
    Keccak_HashInitialize(&h, SHAKE160_R, SHAKE160_C, 0, SHAKE160_P);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBitsIn);
    Keccak_HashFinal(&h, NULL);
    Keccak_HashSqueeze(&h, md, nOutBytes * 8);

    return nOutBytes;
}

int SHAKE80(const unsigned char *dataIn, size_t nBitsIn, unsigned char *md, int nOutBytes)
{
    Keccak_HashInstance h;

    if (md == NULL || nOutBytes == 0) {
        return 0;
    }
    if (nOutBytes > SHAKE_MAX_BITS / 8) {
        nOutBytes = SHAKE_MAX_BITS / 8;
    }
    Keccak_HashInitialize(&h, SHAKE80_R, SHAKE80_C, 0, SHAKE80_P);
    Keccak_HashUpdate(&h, dataIn, (DataLength)nBitsIn);
    Keccak_HashFinal(&h, NULL);
    Keccak_HashSqueeze(&h, md, nOutBytes * 8);

    return nOutBytes;
}

