// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <vector>

#include <openssl/ripemd.h>
#include <openssl/sha.h>

#define USE_SHA3

#ifdef USE_SHA3
#include "keccak/sha3.h"

#define SHAKE320_L  320  // Length in bits
#define KPROOF_OF_WORK_SZ  (SHAKE320_R / 8 * 546)  // KryptoHash Proof of Work Size in bits. It must be a multiple of Keccak Rate.

class CHashWriter
{
private:
    Keccak_HashInstance h;

public:
    int nType;
    int nVersion;

    void Init() {
        Keccak_HashInitialize(&h, SHAKE320_R, SHAKE320_C, 0, SHAKE320_P);
    }

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    CHashWriter& write(const char *pch, size_t size) {
        Keccak_HashUpdate(&h, (BitSequence *)pch, size*8);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash256() {
        uint256 hash;
        Keccak_HashFinal(&h, NULL);
        Keccak_HashSqueeze(&h, (unsigned char*)&hash, 256);
        return hash;
    }

    uint320 GetHash() {
        uint320 hash;
        Keccak_HashFinal(&h, NULL);
        Keccak_HashSqueeze(&h, (unsigned char*)&hash, SHAKE320_L);
        return hash;
    }

    uint320 GetKryptoHash() {
        unsigned char scratchpad[KPROOF_OF_WORK_SZ];
        Keccak_HashFinal(&h, NULL);
        Keccak_HashSqueeze(&h, scratchpad, sizeof(scratchpad));
        uint320 hash;
        SHAKE320(scratchpad, sizeof(scratchpad) * 8, (unsigned char*)&hash, SHAKE320_L / 8);
        return hash;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

template<typename T1>
inline uint320 KryptoHash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = { 0 };
    unsigned char scratchpad[KPROOF_OF_WORK_SZ];
    SHAKE320((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]) * 8, scratchpad, sizeof(scratchpad));
    uint320 hash;
    SHAKE320(scratchpad, sizeof(scratchpad) * 8, (unsigned char*)&hash, SHAKE320_L / 8);
    return hash;
}

template<typename T1>
inline uint320 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint320 hash;
    SHAKE320((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]) * 8, (unsigned char*)&hash, sizeof(hash));
    return hash;
}

template<typename T1, typename T2>
inline uint320 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint320 hash;
    Keccak_HashInstance h;

    Keccak_HashInitialize(&h, SHAKE320_R, SHAKE320_C, 0, SHAKE320_P);
    Keccak_HashUpdate(&h, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]) * 8);
    Keccak_HashUpdate(&h, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]) * 8);
    Keccak_HashFinal(&h, NULL);
    Keccak_HashSqueeze(&h, (unsigned char*)&hash, SHAKE320_L);
    return hash;
}

template<typename T1, typename T2, typename T3>
inline uint320 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint320 hash;
    Keccak_HashInstance h;

    Keccak_HashInitialize(&h, SHAKE320_R, SHAKE320_C, 0, SHAKE320_P);
    Keccak_HashUpdate(&h, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]) * 8);
    Keccak_HashUpdate(&h, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]) * 8);
    Keccak_HashUpdate(&h, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]) * 8);
    Keccak_HashFinal(&h, NULL);
    Keccak_HashSqueeze(&h, (unsigned char*)&hash, SHAKE320_L);
    return hash;
}

template<typename T>
uint320 SerializeHash(const T& obj, int nType = SER_GETHASH, int nVersion = PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

template<typename T>
uint320 SerializeKryptoHash(const T& obj, int nType = SER_GETHASH, int nVersion = PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetKryptoHash();
}

class CHashWriter256
{
private:
    Keccak_HashInstance h;

public:
    int nType;
    int nVersion;

    void Init() {
        Keccak_HashInitialize_SHA3_256(&h);
    }

    CHashWriter256(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    CHashWriter256& write(const char *pch, size_t size) {
        Keccak_HashUpdate(&h, (BitSequence *)pch, size * 8);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 hash1;
        Keccak_HashFinal(&h, (unsigned char*)&hash1);
        uint256 hash2;
        SHA3_256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
        return hash2;
    }

    template<typename T>
    CHashWriter256& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

template<typename T1>
inline uint256 Hash256(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA3_256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA3_256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2>
inline uint256 Hash256(const T1 p1begin, const T1 p1end,
                       const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    Keccak_HashInstance h;

    Keccak_HashInitialize_SHA3_256(&h);
    Keccak_HashUpdate(&h, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]) * 8);
    Keccak_HashUpdate(&h, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]) * 8);
    Keccak_HashFinal(&h, (unsigned char*)&hash1);
    uint256 hash2;
    SHA3_256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash256(const T1 p1begin, const T1 p1end,
                       const T2 p2begin, const T2 p2end,
                       const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    Keccak_HashInstance h;

    Keccak_HashInitialize_SHA3_256(&h);
    Keccak_HashUpdate(&h, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]) * 8);
    Keccak_HashUpdate(&h, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]) * 8);
    Keccak_HashUpdate(&h, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]) * 8);
    Keccak_HashFinal(&h, (unsigned char*)&hash1);
    uint256 hash2;
    SHA3_256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash256(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter256 ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}


template<typename T1>
inline uint224 Hash224(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint224 hash;
    SHA3_224((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash);
    return hash;
}

inline uint224 Hash224(const std::vector<unsigned char>& vch)
{
    return Hash224(vch.begin(), vch.end());
}

template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA3_256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1>
inline uint160 Shake160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint160 hash;
    SHAKE160((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]) * 8, (unsigned char*)&hash, sizeof(hash));
    return hash;
}

inline uint160 Shake160(const std::vector<unsigned char>& vch)
{
    return Shake160(vch.begin(), vch.end());
}

typedef struct
{
    Keccak_HashInstance hInner;
    Keccak_HashInstance hOuter;
} HMAC_SHA3_512_CTX;

int HMAC_SHA3_512_Init(HMAC_SHA3_512_CTX *pctx, const void *pkey, size_t len);
int HMAC_SHA3_512_Update(HMAC_SHA3_512_CTX *pctx, const void *pdata, size_t len);
int HMAC_SHA3_512_Final(unsigned char *pmd, HMAC_SHA3_512_CTX *pctx);

#else

template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

class CHashWriter
{
private:
    SHA256_CTX ctx;

public:
    int nType;
    int nVersion;

    void Init() {
        SHA256_Init(&ctx);
    }

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    CHashWriter& write(const char *pch, size_t size) {
        SHA256_Update(&ctx, pch, size);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 hash1;
        SHA256_Final((unsigned char*)&hash1, &ctx);
        uint256 hash2;
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
        return hash2;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};


template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType = SER_GETHASH, int nVersion = PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

#endif

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);

typedef struct
{
    SHA512_CTX ctxInner;
    SHA512_CTX ctxOuter;
} HMAC_SHA512_CTX;

int HMAC_SHA512_Init(HMAC_SHA512_CTX *pctx, const void *pkey, size_t len);
int HMAC_SHA512_Update(HMAC_SHA512_CTX *pctx, const void *pdata, size_t len);
int HMAC_SHA512_Final(unsigned char *pmd, HMAC_SHA512_CTX *pctx);

#endif
