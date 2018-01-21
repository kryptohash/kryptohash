// Copyright (c) 2014 Kryptohash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KRYPTOHASH_GENESIS_H
#define KRYPTOHASH_GENESIS_H

#include <map>
#include <stdint.h>
#include "uint256.h"

/*
 * These are compiled-in genesis blocks for each available zone.
 */

class CGenesis
{
public:
    int64_t  nTxTime;
    uint32_t nNonce;
    uint320  nHash;

    CGenesis() : nTxTime(0), nNonce(0), nHash(0) {}

    CGenesis(int64_t time, uint32_t nonce, uint320 hash) {
        nTxTime = time;
        nNonce = nonce;
        nHash = hash;
    }

    CGenesis& operator=(const CGenesis& rhs) {
        nTxTime = rhs.nTxTime;
        nNonce = rhs.nNonce;
        nHash = rhs.nHash;
        return *this;
    }
};

namespace Genesis
{

    // Returns true if zone contains a genesis block
    bool GetGenesisData(uint8_t nZone, CGenesis& data);

}

#endif
